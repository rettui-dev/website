import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, MAX_NODE_LINKS } from '../lib/config.js';
import { Monitor } from '../lib/monitor.js';
import { createApp } from '../lib/app.js';
import { createManageClient } from '../lib/manage.js';
import { publicStats } from '../lib/public-api.js';
import { cleanReticulum } from '../lib/manage-api.js';
import { DETECT_LINKS_DEFAULT, LINKS_ACTOR, LINKS_INTERVAL_MS, LINKS_KEEP_MS, LINKS_MAX_BACKOFF_INTERVALS, LinkWatcher, MAX_LINKS, buildLinks, clientTargets, detectLinks, hostOfUrl, linkEntries, matchTarget, normHost } from '../lib/links.js';
import { RESERVED_NAMES, UserStore, reservedName } from '../lib/users.js';
import { hashPassword } from '../lib/password.js';
import { fakeHasher } from './helpers/fake-hasher.js';
import { startManageNode } from './helpers/manage-node.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SECRET = 'links-test-secret-0123456789abcdef-xyz';

// Nodes for the matching tests. Front dials Back over WireGuard: Back's manage_url is on 10.77.2.1.
const entries = [
  { key: 'front.example.net:4242', name: 'Front', host: 'front.example.net', port: 4242, manageHost: '10.77.1.1', statsHost: 'front.example.net' },
  { key: 'back.example.net:4242', name: 'Back', host: 'back.example.net', port: 4242, manageHost: '10.77.2.1', statsHost: '10.77.2.1' },
  { key: 'side.example.net:4242', name: 'Side', host: 'side.example.net', port: 4242, manageHost: null, statsHost: 'stats.side.example.net' },
];
const FRONT = entries[0].key;
const BACK = entries[1].key;
const SIDE = entries[2].key;

test('matching: (a) the address, host in any case and port as a number', () => {
  assert.deepEqual(matchTarget(entries, FRONT, 'BACK.Example.NET', 4242), { key: BACK });
  assert.deepEqual(matchTarget(entries, FRONT, 'back.example.net.', 4242), { key: BACK });
  // The port is part of (a): a different port falls through to (b) and (c), which do not know the name.
  assert.equal(matchTarget(entries, FRONT, 'back.example.net', 4243), null);
});

test('matching: (b) the host of the manage_url, whatever the port (a WireGuard setup)', () => {
  assert.deepEqual(matchTarget(entries, FRONT, '10.77.2.1', 4243), { key: BACK });
  assert.deepEqual(matchTarget(entries, FRONT, '10.77.2.1', 1), { key: BACK });
});

test('matching: (c) the host of the stats_url, after (a) and (b)', () => {
  assert.deepEqual(matchTarget(entries, FRONT, 'Stats.Side.Example.net', 9), { key: SIDE });
  // (b) comes before (c): Back's stats host equals its manage host here, still one node.
  assert.deepEqual(matchTarget(entries, FRONT, '10.77.2.1', 9), { key: BACK });
  const order = [{ ...entries[0] }, { key: 'x:1', name: 'X', host: 'x', port: 1, manageHost: 'shared.example.net', statsHost: null }, { key: 'y:1', name: 'Y', host: 'y', port: 1, manageHost: null, statsHost: 'shared.example.net' }];
  assert.deepEqual(matchTarget(order, FRONT, 'shared.example.net', 5), { key: 'x:1' });
});

test('matching: a host that matches several nodes is dropped, never guessed; so is an unknown one', () => {
  const twins = [...entries, { key: 'back2.example.net:4242', name: 'Back 2', host: 'back2.example.net', port: 4242, manageHost: '10.77.2.1', statsHost: null }];
  assert.deepEqual(matchTarget(twins, FRONT, '10.77.2.1', 4243), { ambiguous: true });
  // An exact address still wins over the shared manage host.
  assert.deepEqual(matchTarget(twins, FRONT, 'back.example.net', 4242), { key: BACK });
  assert.equal(matchTarget(entries, FRONT, 'hub.example.org', 4965), null);
});

test('matching: a node never links to itself', () => {
  assert.equal(matchTarget(entries, FRONT, 'front.example.net', 4242), null);
  assert.equal(matchTarget(entries, FRONT, '10.77.1.1', 4999), null);
  assert.equal(matchTarget(entries, FRONT, 'front.example.net', 9), null);
});

const iface = (name, keys) => ({ path: ['interfaces', name], keys: Object.entries(keys).map(([key, value]) => ({ key, value, set: value !== null })) });
const view = (sections, extra = {}) => cleanReticulum({ revision: 'a'.repeat(32), shared_instance: false, truncated: false, sections, editable: [], ...extra });

test('detection: client interfaces with a target host and port, enabled as the interface says', () => {
  const ret = view([
    iface('A', { type: 'TCPClientInterface', target_host: '10.77.2.1', target_port: '4243', enabled: 'yes' }),
    iface('B', { type: 'TCPClientInterface', target_host: 'side.example.net', target_port: '4242', interface_enabled: 'No' }),
    iface('Server', { type: 'TCPServerInterface', listen_port: '4242', listen_ip: '0.0.0.0' }),
    iface('NoPort', { type: 'TCPClientInterface', target_host: 'back.example.net' }),
    iface('BadPort', { type: 'TCPClientInterface', target_host: 'back.example.net', target_port: '70000' }),
    iface('Hidden', { type: 'TCPClientInterface', target_host: null, target_port: '4242' }),
  ]);
  assert.deepEqual(clientTargets(ret).map((t) => [t.host, t.port, t.enabled]), [['10.77.2.1', 4243, true], ['side.example.net', 4242, false]]);
  const d = detectLinks(ret, entries, FRONT);
  assert.deepEqual(d.links, [{ to: BACK, enabled: true }, { to: SIDE, enabled: false }]);
  assert.equal(d.readable, true);
});

test('detection: two interfaces to one node are one link, on if any is on; unknown on and off is unknown', () => {
  const two = (a, b) => detectLinks(view([iface('A', { target_host: 'back.example.net', target_port: '4242', enabled: a }), iface('B', { target_host: '10.77.2.1', target_port: '4243', enabled: b })]), entries, FRONT).links;
  assert.deepEqual(two('no', 'yes'), [{ to: BACK, enabled: true }]);
  assert.deepEqual(two('no', 'no'), [{ to: BACK, enabled: false }]);
  assert.deepEqual(two('no', 'maybe'), [{ to: BACK, enabled: null }]);
});

test('detection: no view, a shared instance or a cut view give no certainty, and nothing from a program section', () => {
  assert.deepEqual(detectLinks(null, entries, FRONT), { links: [], readable: false, ambiguous: 0 });
  const shared = detectLinks(view([iface('A', { target_host: 'back.example.net', target_port: '4242' })], { shared_instance: true }), entries, FRONT);
  assert.deepEqual([shared.links, shared.readable], [[], false]);
  const cut = detectLinks(view([iface('A', { target_host: 'back.example.net', target_port: '4242' })], { truncated: true }), entries, FRONT);
  assert.deepEqual([cut.links.length, cut.readable], [1, false]);
  const pipe = detectLinks(view([iface('P', { type: 'PipeInterface', target_host: 'back.example.net', target_port: '4242', command: 'nc evil 1' })]), entries, FRONT);
  assert.deepEqual(pipe.links, []);
});

test('detection: a key the node set but does not show has no value, so it is no target and no switch', () => {
  const hidden = (key) => ({ key, value: null, set: true });
  const shown = (key, value) => ({ key, value, set: true });
  const ret = (keys) => view([{ path: ['interfaces', 'H'], keys }]);
  assert.deepEqual(clientTargets(ret([shown('target_host', 'back.example.net'), hidden('target_port')])), []);
  assert.deepEqual(clientTargets(ret([hidden('target_host'), shown('target_port', '4242')])), []);
  // A switch with no shown value could be on: not known.
  assert.deepEqual(clientTargets(ret([shown('target_host', 'back.example.net'), shown('target_port', '4242'), hidden('enabled')])).map((t) => t.enabled), [null]);
  // A key that is not set at all is no key.
  assert.deepEqual(clientTargets(ret([shown('target_host', 'back.example.net'), shown('target_port', '4242'), { key: 'enabled', value: 'yes', set: false }])).map((t) => t.enabled), [false]);
});

// How Reticulum itself reads enabled (rsReticulum config.rs: interface_enabled() is true when either
// key parses as true, and a section with neither is not started).
test('enabled: true, yes, on and 1 are on in any case; false, no, off and 0 are off', () => {
  const on = (value) => clientTargets(view([iface('A', { target_host: 'back.example.net', target_port: '4242', enabled: value })]))[0].enabled;
  for (const v of ['true', 'True', 'YES', 'on', 'On']) assert.equal(on(v), true, v);
  for (const v of ['false', 'False', 'no', 'NO', 'off', 'Off']) assert.equal(on(v), false, v);
  // The node's view shows only yes, no, true, false, on and off: a 1 or a 0 comes without its value.
  assert.equal(on(null), false, 'a key that is not there is off');
  for (const v of ['maybe', '', '2']) assert.equal(on(v), null, JSON.stringify(v));
});

test('enabled: missing means off, interface_enabled counts, and with both keys either one being on is on', () => {
  const of = (keys) => clientTargets(view([iface('A', { target_host: 'back.example.net', target_port: '4242', ...keys })]))[0].enabled;
  assert.equal(of({}), false, 'Reticulum does not start a section with neither key');
  assert.equal(of({ interface_enabled: 'yes' }), true);
  assert.equal(of({ interface_enabled: 'no' }), false);
  assert.equal(of({ enabled: 'no', interface_enabled: 'yes' }), true);
  assert.equal(of({ enabled: 'yes', interface_enabled: 'no' }), true);
  assert.equal(of({ enabled: 'no', interface_enabled: 'off' }), false);
  assert.equal(of({ enabled: 'no', interface_enabled: 'maybe' }), null, 'the other could be on');
  assert.equal(of({ enabled: 'yes', interface_enabled: 'maybe' }), true);
});

// One spelling for a host, on both sides of a match.

test('hosts: IPv6 is compared in one form, with or without brackets, in any case and length', () => {
  assert.equal(normHost('2001:db8:0:0:0:0:0:1'), normHost('2001:DB8::1'));
  assert.equal(normHost('[2001:db8::1]'), normHost('2001:db8::1'));
  assert.equal(normHost('[::1]'), normHost('0:0:0:0:0:0:0:1'));
  assert.equal(normHost('::FFFF:127.0.0.1'), normHost('::ffff:7f00:1'));
  assert.equal(normHost('fd00:77::2:1'), 'fd00:77::2:1');
  assert.equal(hostOfUrl('http://[FD00:0077:0:0:0:0:2:1]:8750'), 'fd00:77::2:1');
});

test('hosts: odd IPv4 forms, a trailing dot, case and spaces', () => {
  assert.equal(normHost('0x7f.1'), '127.0.0.1');
  assert.equal(normHost('127.1'), '127.0.0.1');
  assert.equal(normHost('2130706433'), '127.0.0.1');
  assert.equal(normHost('Back.Example.NET.'), 'back.example.net');
  assert.equal(normHost('  10.77.2.1 '), '10.77.2.1');
  // What the URL parser refuses stays as it was (lower case), so it still compares with itself.
  assert.equal(normHost('fe80::1%eth0'), 'fe80::1%eth0');
  assert.equal(normHost(''), '');
  assert.equal(hostOfUrl('not a url'), null);
});

test('hosts: an interface target and a manage_url host match whatever the spelling', () => {
  const v6 = [{ key: 'v6:1', name: 'V6', host: 'v6', port: 1, manageHost: hostOfUrl('http://[fd00:77::2:1]:8750'), statsHost: null }];
  for (const target of ['FD00:0077:0000:0000:0000:0000:0002:0001', '[fd00:77::2:1]', 'fd00:77:0::2:1']) assert.deepEqual(matchTarget(v6, 'x:1', target, 4243), { key: 'v6:1' }, target);
  const v4 = [{ key: 'v4:1', name: 'V4', host: 'v4', port: 1, manageHost: hostOfUrl('http://127.1:8750'), statsHost: null }];
  assert.deepEqual(matchTarget(v4, 'x:1', '0x7f.0.0.1.', 4243), { key: 'v4:1' });
  const ents = linkEntries({ targets: [{ host: 'back.example.net', port: 4242 }], manage: new Map(), statsUrls: new Map() });
  assert.deepEqual(matchTarget(ents, 'x:1', 'back.example.net.', 4242), { key: 'back.example.net:4242' });
});

test('matching: the stats host step does not apply to a host that is the address host of a node (a name behind a proxy)', () => {
  const behind = [
    { key: 'rns.example.org:4242', name: 'Proxy', host: 'rns.example.org', port: 4242, manageHost: null, statsHost: null },
    { key: 'back.example.org:4242', name: 'Back', host: 'back.example.org', port: 4242, manageHost: null, statsHost: 'rns.example.org' },
  ];
  assert.equal(matchTarget(behind, 'x:1', 'rns.example.org', 9999), null, 'not Back');
  assert.deepEqual(matchTarget(behind, 'x:1', 'rns.example.org', 4242), { key: 'rns.example.org:4242' });
  const own = [{ ...behind[1], statsHost: 'stats.back.example.org' }];
  assert.deepEqual(matchTarget(own, 'x:1', 'stats.back.example.org', 9), { key: 'back.example.org:4242' });
});

test('detection: an ambiguous target is counted, not kept', () => {
  const twins = [...entries, { key: 'b2:1', name: 'B2', host: 'b2', port: 1, manageHost: '10.77.2.1', statsHost: null }];
  const d = detectLinks(view([iface('A', { target_host: '10.77.2.1', target_port: '9' })]), twins, FRONT);
  assert.deepEqual([d.links, d.ambiguous], [[], 1]);
});

// Merge

const K = ['a:1', 'b:1', 'c:1', 'd:1'];
const det = (map) => (k) => map[k] ?? null;
const dec = (map) => (k) => map[k] ?? [];
const ok = (links, readable = true) => ({ links, readable });
const L = (to, enabled = true) => ({ to, enabled });

test('merge: detected links are published with the flags and nothing else', () => {
  const out = buildLinks(K, dec({}), det({ 'a:1': ok([L('b:1'), L('c:1', false)]) }));
  assert.deepEqual(out.get('a:1'), [
    { to: 'b:1', dir: 'dials', enabled: true, source: 'detected', conflict: null },
    { to: 'c:1', dir: 'dials', enabled: false, source: 'detected', conflict: null },
  ]);
  assert.deepEqual(out.get('b:1'), []);
});

test('merge: both agree: drawn as detected, and the detected on or off wins', () => {
  const out = buildLinks(K, dec({ 'a:1': [{ to: 'b:1', dir: 'dials' }] }), det({ 'a:1': ok([L('b:1', false)]) }));
  assert.deepEqual(out.get('a:1'), [{ to: 'b:1', dir: 'dials', enabled: false, source: 'detected', conflict: null }]);
  // A declared "unknown" never disagrees with a detected direction.
  const u = buildLinks(K, dec({ 'a:1': [{ to: 'b:1', dir: 'unknown' }] }), det({ 'b:1': ok([L('a:1')]) }));
  assert.deepEqual([u.get('a:1'), u.get('b:1')], [[], [{ to: 'a:1', dir: 'dials', enabled: true, source: 'detected', conflict: null }]]);
});

test('merge: a link declared on one node stays when the other node detects the opposite direction; both are drawn', () => {
  const out = buildLinks(K, dec({ 'a:1': [{ to: 'b:1', dir: 'dials' }] }), det({ 'b:1': ok([L('a:1')]) }));
  assert.deepEqual(out.get('a:1'), [{ to: 'b:1', dir: 'dials', enabled: null, source: 'declared', conflict: null }]);
  assert.deepEqual(out.get('b:1'), [{ to: 'a:1', dir: 'dials', enabled: true, source: 'detected', conflict: null }]);
  // The same with the dialling node's complete config showing no such interface.
  const nf = buildLinks(K, dec({ 'a:1': [{ to: 'b:1', dir: 'dials' }] }), det({ 'a:1': ok([]), 'b:1': ok([L('a:1')]) }));
  assert.equal(nf.get('a:1')[0].conflict, 'not_found');
  assert.equal(nf.get('b:1')[0].conflict, null);
  // The node's own config still wins over its own declaration.
  const own = buildLinks(K, dec({ 'a:1': [{ to: 'b:1', dir: 'dials' }] }), det({ 'a:1': ok([L('b:1', false)]), 'b:1': ok([L('a:1')]) }));
  assert.deepEqual(own.get('a:1'), [{ to: 'b:1', dir: 'dials', enabled: false, source: 'detected', conflict: null }]);
  // Declared both ways, detected one way: each node keeps its own.
  const both = buildLinks(K, dec({ 'a:1': [{ to: 'b:1', dir: 'dials' }], 'b:1': [{ to: 'a:1', dir: 'dials' }] }), det({ 'b:1': ok([L('a:1')]) }));
  assert.equal(both.get('b:1')[0].conflict, null);
  assert.deepEqual(both.get('a:1'), [{ to: 'b:1', dir: 'dials', enabled: null, source: 'declared', conflict: null }]);
});

test('merge: declared only is kept; not_found only when the dialling node config was complete', () => {
  const declared = dec({ 'a:1': [{ to: 'b:1', dir: 'dials' }] });
  const one = (d) => buildLinks(K, declared, det(d)).get('a:1')[0];
  assert.deepEqual(one({}), { to: 'b:1', dir: 'dials', enabled: null, source: 'declared', conflict: null });
  assert.equal(one({ 'a:1': ok([]) }).conflict, 'not_found');
  assert.equal(one({ 'a:1': ok([], false) }).conflict, null, 'a cut or shared view proves nothing');
  assert.equal(one({ 'b:1': ok([]) }).conflict, null, 'only the dialling node counts');
  // An unknown direction needs both configs.
  const unk = dec({ 'a:1': [{ to: 'b:1', dir: 'unknown' }] });
  const two = (d) => buildLinks(K, unk, det(d)).get('a:1')[0];
  assert.equal(two({ 'a:1': ok([]) }).conflict, null);
  assert.equal(two({ 'a:1': ok([]), 'b:1': ok([]) }).conflict, 'not_found');
  assert.equal(two({ 'a:1': ok([]), 'b:1': ok([]) }).dir, 'unknown');
});

test('merge: self links, unknown targets and the cap', () => {
  const out = buildLinks(K, dec({ 'a:1': [{ to: 'a:1', dir: 'dials' }, { to: 'zzz:9', dir: 'dials' }] }), det({ 'a:1': ok([L('a:1'), L('nowhere:1')]) }));
  assert.deepEqual(out.get('a:1'), []);
  const keys = Array.from({ length: 12 }, (_, i) => `n${i}:1`);
  const many = buildLinks(keys, dec({ 'n0:1': keys.slice(1).map((to) => ({ to, dir: 'dials' })) }), det({ 'n0:1': ok(keys.slice(6).map((to) => L(to))) }));
  const list = many.get('n0:1');
  assert.equal(list.length, MAX_LINKS);
  // Detected links come first when there are too many.
  assert.equal(list.filter((l) => l.source === 'detected').length, 6);
});

// Config

const one = (extra) => `nodes:\n  - address: a.test:1\n    name: Alpha\n${extra}  - address: b.test:1\n    name: Beta\n  - address: c.test:1\n`;
const bad = (text, pattern) => assert.throws(() => loadConfig(text), (e) => e instanceof Error && pattern.test(e.message), text);

test('config: links resolve by name (any case) or address, and a node without any has no key', () => {
  const c = loadConfig(one('    links:\n      - to: beta\n      - to: C.test:1\n        direction: unknown\n'));
  assert.deepEqual(c.nodes.get('a.test:1').links, [{ to: 'b.test:1', dir: 'dials' }, { to: 'c.test:1', dir: 'unknown' }]);
  assert.equal(Object.hasOwn(c.nodes.get('b.test:1'), 'links'), false);
});

test('config: unknown target, self link, repeats, the cap and wrong types stop the server', () => {
  bad(one('    links:\n      - to: Nobody\n'), /links\[1\]\.to "Nobody" is not the name or the address of a monitored node/);
  bad(one('    links:\n      - to: d.test:1\n'), /not the name or the address/);
  bad(one('    links:\n      - to: Alpha\n'), /links a\.test:1 to itself/);
  bad(one('    links:\n      - to: a.test:1\n'), /to itself/);
  bad(one('    links:\n      - to: Beta\n      - to: b.test:1\n'), /lists b\.test:1 twice/);
  bad(one('    links: []\n'), /list of 1 to 8 links/);
  bad(one('    links: Beta\n'), /list of 1 to 8 links/);
  bad(one(`    links:\n${Array.from({ length: MAX_NODE_LINKS + 1 }, () => '      - to: Beta\n').join('')}`), /list of 1 to 8 links/);
  bad(one('    links: [Beta]\n'), /links\[1\] must be a map/);
  bad(one('    links:\n      - to: 5\n'), /to must be the name or the address/);
  bad(one('    links:\n      - direction: dials\n'), /to must be the name/);
  bad(one('    links:\n      - to: Beta\n        direction: both\n'), /direction must be dials or unknown/);
  bad(one('    links:\n      - to: Beta\n        enabled: false\n'), /unknown key "enabled"/);
  bad(one('    links:\n      - to: "Be\\u0007ta"\n'), /control characters/);
  bad('links: []\nnodes:\n  - address: a.test:1\n', /unknown key "links" at the top level/);
  // Two nodes with one name: use the address.
  bad('nodes:\n  - address: a.test:1\n    name: Same\n    links:\n      - to: same\n  - address: b.test:1\n    name: Same\n  - address: c.test:1\n    name: SAME\n', /name of more than one node/);
});

test('config: links is accepted in require_login and is in the default that locks every section once there are users', () => {
  const users = "users:\n  - name: alice\n    password_hash: '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g'\n";
  const c = loadConfig(`${users}require_login: [details, links]\nnodes:\n  - address: a.test:1\n`);
  assert.deepEqual(c.defaults.requireLogin, ['details', 'links']);
  assert.deepEqual(loadConfig(`${users}nodes:\n  - address: a.test:1\n`).defaults.requireLogin, ['details', 'storage', 'peers', 'disk', 'versions', 'links']);
  // An explicit list replaces the default, and so does a node's own.
  assert.equal(loadConfig(`${users}require_login: [details]\nnodes:\n  - address: a.test:1\n`).defaults.requireLogin.includes('links'), false);
  assert.deepEqual(loadConfig(`${users}nodes:\n  - address: a.test:1\n    require_login: [details]\n`).nodes.get('a.test:1').requireLogin, ['details']);
  assert.deepEqual(loadConfig('nodes:\n  - address: a.test:1\n').defaults.requireLogin, []);
  bad(`${users}require_login: [links, links]\nnodes:\n  - address: a.test:1\n`, /lists links twice/);
  bad(`${users}require_login: [nope]\nnodes:\n  - address: a.test:1\n`, /must be one of .*links/);
});

test('config: detect_links is off unless the operator turns it on, and is a top-level true or false', () => {
  assert.equal(DETECT_LINKS_DEFAULT, false);
  assert.equal(loadConfig('nodes:\n  - address: a.test:1\n').detectLinks, DETECT_LINKS_DEFAULT);
  assert.equal(loadConfig('detect_links: true\nnodes:\n  - address: a.test:1\n').detectLinks, true);
  assert.equal(loadConfig('detect_links: false\nnodes:\n  - address: a.test:1\n').detectLinks, false);
  bad('detect_links: yes please\nnodes:\n  - address: a.test:1\n', /detect_links must be true or false/);
  bad('detect_links: 1\nnodes:\n  - address: a.test:1\n', /detect_links must be true or false/);
  bad('nodes:\n  - address: a.test:1\n    detect_links: true\n', /unknown key "detect_links"/);
});

test('the example config documents links in a form that is valid when uncommented', async () => {
  const text = await fs.readFile(path.join(root, 'config.example.yaml'), 'utf8');
  assert.match(text, /^ {4}# links:$/m);
  const on = text.replace(/^ {4}# ( *)(links:|- to: .*|direction: \w+)$/gm, '    $1$2').replace(/^ {4} {0}( {2}- to:)/gm, '    $1');
  const c = loadConfig(on);
  const front = [...c.nodes.values()].find((n) => n.links?.length);
  assert.deepEqual(front.links.map((l) => l.dir), ['dials', 'unknown']);
});

// The monitor: what is published

const dataDir = () => fs.mkdtemp(path.join(os.tmpdir(), 'website-'));

async function monitorOf(configText, watcher = null, opts = {}) {
  const c = loadConfig(configText);
  const monitor = new Monitor({ targets: c.targets, nodes: c.nodes, statsUrls: c.statsUrls, dataDir: await dataDir(), requireLogin: c.defaults.requireLogin, probeFn: async () => ({ up: true, ms: 1 }), ...opts });
  if (watcher) monitor.attachLinks(watcher);
  await monitor.checkAll();
  return monitor;
}

const fakeSource = (map) => ({ detected: (k) => map[k] ?? null });

test('snapshot: a visitor gets to and dir only; a signed-in viewer also gets the source and conflict', async () => {
  const m = await monitorOf(`${USERS}require_login: []\nnodes:\n  - address: a.test:1\n    links:\n      - to: c.test:1\n  - address: b.test:1\n  - address: c.test:1\n`, fakeSource({ 'b.test:1': ok([L('a.test:1')]) }));
  const [a, b] = m.snapshot(90, false).hosts;
  assert.deepEqual(a.links, [{ to: 'c.test:1', dir: 'dials' }]);
  assert.deepEqual(b.links, [{ to: 'a.test:1', dir: 'dials' }]);
  const [sa, sb] = m.snapshot(90, true).hosts;
  assert.deepEqual(sa.links, [{ to: 'c.test:1', dir: 'dials', enabled: null, source: 'declared', conflict: null }]);
  assert.deepEqual(sb.links, [{ to: 'a.test:1', dir: 'dials', enabled: true, source: 'detected', conflict: null }]);
  const m2 = await monitorOf('nodes:\n  - address: a.test:1\n');
  assert.equal(Object.hasOwn(m2.snapshot().hosts[0], 'links'), false);
});

test('snapshot: a link found in a config is hidden from a visitor when either end keeps its details private, and a signed-in user sees it', async () => {
  const cfg = `${USERS}require_login: []\nnodes:\n  - address: a.test:1\n  - address: b.test:1\n    public_details: false\n  - address: c.test:1\n`;
  const src = fakeSource({ 'a.test:1': ok([L('b.test:1'), L('c.test:1')]), 'b.test:1': ok([L('c.test:1')]) });
  const m = await monitorOf(cfg, src);
  const [a, b, c] = m.snapshot(90, false).hosts;
  assert.deepEqual(a.links, [{ to: 'c.test:1', dir: 'dials' }], 'a to the private b is left out');
  assert.equal(b.links?.length ?? 0, 0, 'the private b dials nothing in public');
  assert.equal(c.links?.length ?? 0, 0);
  const [sa, sb] = m.snapshot(90, true).hosts;
  assert.deepEqual(sa.links.map((l) => l.to), ['b.test:1', 'c.test:1']);
  assert.deepEqual(sb.links.map((l) => l.to), ['c.test:1']);
});

const USERS = "users:\n  - name: alice\n    password_hash: '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g'\n";

test('require_login: links hides them from a visitor, and shows them once signed in', async () => {
  const text = `${USERS}require_login: [links]\nnodes:\n  - address: a.test:1\n    links:\n      - to: b.test:1\n  - address: b.test:1\n    links:\n      - to: c.test:1\n  - address: c.test:1\n`;
  const m = await monitorOf(text);
  assert.equal(m.snapshot(90, false).hosts.some((h) => Object.hasOwn(h, 'links')), false);
  assert.equal(JSON.stringify(m.snapshot(90, false)).includes('b.test:1","dir'), false);
  assert.equal(m.snapshot(90, true).hosts.filter((h) => h.links).length, 2);
});

test('require_login: a link is left out when either end keeps its links locked', async () => {
  const text = `${USERS}nodes:\n  - address: a.test:1\n    require_login: []\n    links:\n      - to: b.test:1\n      - to: c.test:1\n  - address: b.test:1\n    require_login: [links]\n  - address: c.test:1\n    require_login: []\n`;
  const [a] = (await monitorOf(text)).snapshot(90, false).hosts;
  assert.deepEqual(a.links.map((l) => l.to), ['c.test:1']);
});

test('the default that locks every section (users, no rule) hides the links; a list without links, or no users, shows them', async () => {
  const body = 'nodes:\n  - address: a.test:1\n    links:\n      - to: b.test:1\n  - address: b.test:1\n';
  assert.equal(Object.hasOwn((await monitorOf(`${USERS}${body}`)).snapshot(90, false).hosts[0], 'links'), false);
  assert.equal((await monitorOf(`${USERS}${body}`)).snapshot(90, true).hosts[0].links.length, 1);
  assert.equal((await monitorOf(`${USERS}require_login: [details]\n${body}`)).snapshot(90, false).hosts[0].links.length, 1);
  assert.equal((await monitorOf(body)).snapshot(90, false).hosts[0].links.length, 1);
});

test('links found in a node config are hidden from a visitor when the node keeps its details private; declared ones are not', async () => {
  const text = `${USERS}require_login: []\nnodes:\n  - address: a.test:1\n    public_details: false\n    links:\n      - to: c.test:1\n  - address: b.test:1\n  - address: c.test:1\n`;
  const m = await monitorOf(text, fakeSource({ 'a.test:1': ok([L('b.test:1')]) }));
  assert.deepEqual(m.snapshot(90, false).hosts[0].links.map((l) => l.to), ['c.test:1'], 'only the declared one');
  assert.deepEqual(m.snapshot(90, true).hosts[0].links.map((l) => l.to), ['b.test:1', 'c.test:1']);
});

test('links to a node that keeps its links locked are taken out before the cap, so they do not crowd out the rest', async () => {
  const names = Array.from({ length: 17 }, (_, i) => `n${i}.test:1`);
  const locked = names.slice(1, 9);
  const text = `${USERS}require_login: []\nnodes:\n${names.map((n, i) => `  - address: ${n}\n${locked.includes(n) ? '    require_login: [links]\n' : ''}${i === 0 ? `    links:\n${names.slice(9).map((t) => `      - to: ${t}\n`).join('')}` : ''}`).join('')}`;
  // Eight detected links come first under the cap, and all of them end at a locked node.
  const m = await monitorOf(text, fakeSource({ 'n0.test:1': ok(locked.map((t) => L(t))) }));
  assert.deepEqual(m.snapshot(90, false).hosts[0].links.map((l) => l.to), names.slice(9));
  assert.deepEqual(m.snapshot(90, true).hosts[0].links.map((l) => l.to), locked);
});

test('/api/status and the public API: links in the first (public, locked by require_login), never in the second', async () => {
  const m = await monitorOf('nodes:\n  - address: a.test:1\n    links:\n      - to: b.test:1\n  - address: b.test:1\n');
  const server = createApp({ monitor: m, publicDir: path.join(root, 'public') });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const body = await (await fetch(`${base}/api/status`)).json();
    assert.deepEqual(body.hosts[0].links, [{ to: 'b.test:1', dir: 'dials' }]);
    const pub = await (await fetch(`${base}/api/public/stats`)).text();
    assert.equal(pub.includes('links'), false);
    assert.equal(JSON.stringify(publicStats(m.snapshot(1, false), 'x')).includes('"links"'), false);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
});

test('the answer stays small with the most links a node can have, for all 64 nodes', async () => {
  const names = Array.from({ length: 64 }, (_, i) => `n${i}.example.net:4242`);
  const text = 'nodes:\n' + names.map((n, i) => `  - address: ${n}\n    links:\n${[1, 2, 3, 4, 5, 6, 7, 8].map((k) => `      - to: ${names[(i + k) % 64]}\n`).join('')}`).join('');
  const m = await monitorOf(text);
  const hosts = m.snapshot(1, false).hosts;
  assert.ok(hosts.every((h) => h.links.length === 8));
  const per = JSON.stringify(hosts[0].links).length;
  assert.ok(per < 8 * 140, `links are ${per} bytes`);
});

// The watcher

// A stand-in for the signing client: answers from a table and counts what it was asked.
function fakeClient(answers) {
  const calls = [];
  return {
    calls,
    answers,
    has: (k) => Object.hasOwn(answers, k),
    async call(host, method, target, actor) {
      calls.push({ host, method, target, actor });
      const a = answers[host];
      if (a instanceof Error) throw a;
      return typeof a === 'function' ? a() : a;
    },
  };
}
const state = (sections, extra = {}) => ({ ok: true, status: 200, body: { reticulum: { revision: 'a'.repeat(32), shared_instance: false, truncated: false, sections, editable: [], ...extra } } });
const toBack = [iface('A', { type: 'TCPClientInterface', target_host: '10.77.2.1', target_port: '4243', enabled: 'yes' })];

function clock(start = 1_000_000) {
  const c = { t: start, now: () => c.t, tick: (ms) => (c.t += ms) };
  return c;
}

test('watcher: one read-only GET of the state per managed node and round, as its own actor', async () => {
  const client = fakeClient({ [FRONT]: state(toBack), [BACK]: state([]) });
  const w = new LinkWatcher({ client, entries, now: clock().now });
  await w.refresh();
  assert.deepEqual(client.calls.map((c) => [c.host, c.method, c.target, c.actor]).sort(), [[BACK, 'GET', '/manage/v1/state', LINKS_ACTOR], [FRONT, 'GET', '/manage/v1/state', LINKS_ACTOR]]);
  assert.deepEqual(w.detected(FRONT), { at: 1_000_000, links: [{ to: BACK, enabled: true }], readable: true });
  assert.equal(w.detected(SIDE), null, 'a node without management is never asked');
});

test('watcher: a page view never asks a node', async () => {
  const client = fakeClient({ [FRONT]: state(toBack) });
  const w = new LinkWatcher({ client, entries, now: clock().now });
  await w.refresh();
  const m = await monitorOf('nodes:\n  - address: a.test:1\n', w);
  const before = client.calls.length;
  for (let i = 0; i < 200; i++) m.snapshot(90, i % 2 === 0);
  assert.equal(client.calls.length, before);
});

test('watcher: the last good result is kept for a bounded time when a node cannot be reached, then dropped', async () => {
  const c = clock();
  const client = fakeClient({ [FRONT]: state(toBack) });
  const w = new LinkWatcher({ client, entries, now: c.now });
  await w.refresh();
  client.answers[FRONT] = { ok: false, error: 'timeout' };
  c.tick(LINKS_INTERVAL_MS);
  await w.refresh();
  assert.equal(w.detected(FRONT).links.length, 1, 'kept');
  c.tick(LINKS_KEEP_MS - LINKS_INTERVAL_MS);
  assert.equal(w.detected(FRONT).links.length, 1, 'still within the bound');
  c.tick(1);
  assert.equal(w.detected(FRONT), null, 'dropped');
});

test('watcher: failures back off, and a recovery clears it', async () => {
  const c = clock();
  const client = fakeClient({ [FRONT]: { ok: false, error: 'unsigned' } });
  const w = new LinkWatcher({ client, entries, now: c.now });
  await w.refresh();
  c.tick(LINKS_INTERVAL_MS / 2);
  await w.refresh();
  assert.equal(client.calls.length, 1, 'not asked again before the interval');
  c.tick(LINKS_INTERVAL_MS);
  await w.refresh();
  assert.equal(client.calls.length, 2);
  c.tick(LINKS_INTERVAL_MS);
  await w.refresh();
  assert.equal(client.calls.length, 2, 'the second failure waits two intervals');
  c.tick(LINKS_INTERVAL_MS);
  client.answers[FRONT] = state(toBack);
  await w.refresh();
  assert.equal(w.detected(FRONT).links.length, 1);
  c.tick(LINKS_INTERVAL_MS);
  await w.refresh();
  assert.equal(client.calls.length, 4, 'asked every interval again');
});

test('watcher: refusals, a client that throws, odd answers and old nodes never throw and give no links', async () => {
  const client = fakeClient({
    [FRONT]: new Error('boom'),
    [BACK]: { ok: true, status: 429, body: {} },
    [SIDE]: { ok: true, status: 200, body: { version: '1.0.0' } },
  });
  const w = new LinkWatcher({ client, entries, now: clock().now });
  await assert.doesNotReject(() => w.refresh());
  assert.equal(w.detected(FRONT), null);
  assert.equal(w.detected(BACK), null);
  // An older node without the Reticulum view answers, and has no links and no certainty.
  assert.deepEqual(w.detected(SIDE).links, []);
  assert.equal(w.detected(SIDE).readable, false);
});

test('watcher: targets that match no node are dropped before they are kept, and ambiguity is logged without addresses', async () => {
  const twins = [...entries, { key: 'back2.example.net:4242', name: 'Back 2', host: 'back2.example.net', port: 4242, manageHost: '10.77.2.1', statsHost: null }];
  const notes = [];
  const client = fakeClient({ [FRONT]: state([...toBack, iface('Hub', { target_host: 'hub.example.org', target_port: '4965' })]) });
  const w = new LinkWatcher({ client, entries: twins, now: clock().now, debug: (t) => notes.push(t) });
  await w.refresh();
  const kept = JSON.stringify(w.detected(FRONT)) + JSON.stringify(w);
  assert.equal(kept.includes('hub.example.org'), false);
  assert.equal(kept.includes('10.77.2.1'), false);
  assert.equal(notes.length, 1);
  assert.doesNotMatch(notes[0], /10\.77|hub\.example|:4243/);
});

test('watcher: at most four nodes are read at the same time', async () => {
  const many = Array.from({ length: 10 }, (_, i) => ({ key: `n${i}:1`, name: `N${i}`, host: `n${i}`, port: 1, manageHost: null, statsHost: null }));
  let running = 0;
  let peak = 0;
  const answers = Object.fromEntries(many.map((e) => [e.key, async () => (running++, (peak = Math.max(peak, running)), await new Promise((r) => setTimeout(r, 5)), running--, state([]))]));
  const w = new LinkWatcher({ client: fakeClient(answers), entries: many, now: clock().now });
  await w.refresh();
  assert.equal(peak, 4);
});

test('watcher: start reads once after a delay, then every interval, and stop ends it', async () => {
  const client = fakeClient({ [FRONT]: state(toBack) });
  const w = new LinkWatcher({ client, entries, now: Date.now, intervalMs: 30, firstDelayMs: 5 });
  w.start();
  assert.equal(w.running, true);
  await new Promise((r) => setTimeout(r, 120));
  w.stop();
  assert.equal(w.running, false);
  const n = client.calls.length;
  assert.ok(n >= 2, `${n} reads`);
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(client.calls.length, n, 'stopped');
  // Nothing to read: no timer at all.
  const idle = new LinkWatcher({ client: fakeClient({}), entries, now: Date.now });
  idle.start();
  assert.equal(idle.running, false);
});

test('watcher: a reading problem does not touch the uptime checks', async () => {
  const client = fakeClient({ [FRONT]: new Error('boom') });
  const w = new LinkWatcher({ client, entries: [{ ...entries[0], key: 'a.test:1', host: 'a.test', port: 1 }], now: clock().now });
  const m = await monitorOf('nodes:\n  - address: a.test:1\n', w);
  await w.refresh();
  await m.checkAll();
  assert.equal(m.snapshot().hosts[0].status, 'up');
});

test('with the real client and a fake node: found, matched, published; a wrong secret gives nothing', async () => {
  const node = await startManageNode({ secret: SECRET });
  try {
    node.reticulum = { revision: 'b'.repeat(32), shared_instance: false, truncated: false, editable: [], sections: [
      iface('To Back', { type: 'TCPClientInterface', target_host: '10.77.2.1', target_port: '4243', enabled: 'yes', passphrase: 'hunter2' }),
      iface('To Nowhere', { type: 'TCPClientInterface', target_host: 'hub.example.org', target_port: '4965' }),
    ] };
    const ents = linkEntries({
      targets: [{ host: 'front.example.net', port: 4242 }, { host: 'back.example.net', port: 4242 }],
      nodes: new Map([['front.example.net:4242', { name: 'Front' }]]),
      manage: new Map([[FRONT, { url: node.url }], [BACK, { url: 'http://10.77.2.1:8750' }]]),
      statsUrls: new Map(),
    });
    const client = createManageClient({ nodes: new Map([[FRONT, { url: node.url, secret: SECRET }]]) });
    const w = new LinkWatcher({ client, entries: ents });
    await w.refresh();
    assert.deepEqual(w.detected(FRONT).links, [{ to: BACK, enabled: true }]);
    assert.equal(JSON.stringify(w.detected(FRONT)).includes('hunter2'), false);
    assert.equal(JSON.stringify(w).includes('10.77.2.1'), false);
    assert.deepEqual(node.requests.map((r) => [r.method, r.path.split('?')[0], r.actor]), [['GET', '/manage/v1/state', LINKS_ACTOR]]);

    const wrong = new LinkWatcher({ client: createManageClient({ nodes: new Map([[FRONT, { url: node.url, secret: `${SECRET}-other` }]]) }), entries: ents });
    await wrong.refresh();
    assert.equal(wrong.detected(FRONT), null);
  } finally {
    await node.close();
  }
});

test('watcher: a throw inside a read is a failure with backoff, like any other', async () => {
  const c = clock();
  // An answer that is not an object makes the reading itself throw.
  const client = fakeClient({ [FRONT]: { ok: true, status: 200, get body() { throw new Error('boom'); } } });
  const w = new LinkWatcher({ client, entries, now: c.now });
  await assert.doesNotReject(() => w.refresh());
  assert.equal(w.detected(FRONT), null);
  c.tick(LINKS_INTERVAL_MS);
  await w.refresh();
  assert.equal(client.calls.length, 2);
  c.tick(LINKS_INTERVAL_MS);
  await w.refresh();
  assert.equal(client.calls.length, 2, 'the second failure waits two intervals');
  const weird = fakeClient({ [FRONT]: { ok: true, status: 200, body: { reticulum: 5 } }, [BACK]: null });
  const w2 = new LinkWatcher({ client: weird, entries, now: c.now });
  await assert.doesNotReject(() => w2.refresh());
  assert.deepEqual(w2.detected(FRONT).links, []);
  assert.equal(w2.detected(BACK), null);
});

test('watcher: the wait after failures doubles up to the cap and no further', async () => {
  const c = clock();
  const client = fakeClient({ [FRONT]: { ok: false, error: 'network' } });
  const w = new LinkWatcher({ client, entries, now: c.now });
  const at = [];
  for (let round = 0; round < 40; round++) {
    const before = client.calls.length;
    await w.refresh();
    if (client.calls.length > before) at.push(round);
    c.tick(LINKS_INTERVAL_MS);
  }
  const gaps = at.slice(1).map((r, i) => r - at[i]);
  assert.deepEqual(gaps.slice(0, 6), [1, 2, 4, LINKS_MAX_BACKOFF_INTERVALS, LINKS_MAX_BACKOFF_INTERVALS, LINKS_MAX_BACKOFF_INTERVALS]);
  assert.ok(gaps.every((n) => n <= LINKS_MAX_BACKOFF_INTERVALS), gaps.join(','));
});

test('watcher: says once, with the node name and a short code, when it cannot read a node, and once when it can again', async () => {
  const c = clock();
  const notes = [];
  const client = fakeClient({ [FRONT]: { ok: false, error: 'unsigned' } });
  const w = new LinkWatcher({ client, entries, now: c.now, log: (t) => notes.push(t) });
  await w.refresh();
  assert.deepEqual(notes, ['links: cannot read all of Front: unsigned']);
  for (let i = 0; i < 3; i++) {
    c.tick(LINKS_INTERVAL_MS * LINKS_MAX_BACKOFF_INTERVALS);
    await w.refresh();
  }
  assert.equal(notes.length, 1, 'the same state is not said again');
  client.answers[FRONT] = { ok: false, error: 'timeout' };
  c.tick(LINKS_INTERVAL_MS * LINKS_MAX_BACKOFF_INTERVALS);
  await w.refresh();
  assert.equal(notes.at(-1), 'links: cannot read all of Front: timeout');
  client.answers[FRONT] = state(toBack);
  c.tick(LINKS_INTERVAL_MS * LINKS_MAX_BACKOFF_INTERVALS);
  await w.refresh();
  assert.equal(notes.at(-1), 'links: can read Front again');
  // A node that answers without the Reticulum view, or with a shared instance, is said too.
  client.answers[FRONT] = { ok: true, status: 200, body: {} };
  c.tick(LINKS_INTERVAL_MS);
  await w.refresh();
  assert.equal(notes.at(-1), 'links: cannot read all of Front: no-reticulum-view');
  assert.equal(notes.every((t) => !/10\.77|:\d{4}|http|\//.test(t.replace('links: ', ''))), true, notes.join('\n'));
  // A refusal with a status is a code, and nothing the node said is repeated.
  const odd = fakeClient({ [FRONT]: { ok: true, status: 429, body: { error: 'see http://10.77.1.1/x' } } });
  const seen = [];
  await new LinkWatcher({ client: odd, entries, now: c.now, log: (t) => seen.push(t) }).refresh();
  assert.deepEqual(seen, ['links: cannot read all of Front: status-429']);
});

test('watcher: nothing a dump of it or of the entries shows holds a host', async () => {
  const w = new LinkWatcher({ client: fakeClient({ [FRONT]: state(toBack) }), entries, now: clock().now });
  await w.refresh();
  assert.equal(JSON.stringify(w), '{}');
  assert.deepEqual(Object.keys(w), []);
});

// Reserved names

test('the name status-links is reserved, in any case, for users of the store, the config file and the command line', async () => {
  assert.deepEqual(RESERVED_NAMES, [LINKS_ACTOR]);
  for (const name of ['status-links', 'Status-Links', 'STATUS-LINKS']) assert.equal(reservedName(name), true, name);
  for (const name of ['status-link', 'status-links2', 'my-status-links', 'alice', 5, null]) assert.equal(reservedName(name), false, String(name));
  const store = new UserStore({ db: null, data: { users: [] }, configUsers: [], keys: null });
  const h = await hashPassword('correct horse battery', undefined, fakeHasher);
  for (const name of ['status-links', 'Status-Links']) {
    const err = await store.createUser({ name, passwordHash: h, role: 'viewer' }).then(() => null, (e) => e);
    assert.equal(err?.code, 'reserved-name', name);
    assert.match(err.message, /reserved for the website itself/);
  }
  const phc = `'${h}'`;
  bad(`users:\n  - name: Status-Links\n    password_hash: ${phc}\nnodes:\n  - address: a.test:1\n`, /users\[1\]\.name "Status-Links" is reserved for the website itself/);
  const { parseArgs } = await import('../scripts/users.js');
  assert.throws(() => parseArgs(['create', 'STATUS-links', '--role', 'admin']), /reserved for the website itself/);
  // An existing user of that name can still be looked at and removed.
  assert.doesNotThrow(() => parseArgs(['delete', 'status-links']));
});
