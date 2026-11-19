import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// status.js is a browser script; with no document it exposes its pure helpers.
const file = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public', 'status.js');
const sandbox = { Date, Math };
sandbox.globalThis = sandbox;
vm.runInNewContext(fs.readFileSync(file, 'utf8'), sandbox);
const { ago, barLabel, bytes, duration, nodeStatPairs, formatRate, niceTicks, runs, summarize, summaryText, axisTime, peerShares, versionSummary, count, intervalWords,
  hostKey, displayName, showBadges, badgeText, badgeTitle, groupHosts, peerRange, peerNote, groupCoverage, groupPairs, peerRangeRows,
  gapLimit, nearestIndex, timeAt, tooltipTitle, tooltipRows, tooltipSpeech, tooltipPosition } =
  sandbox.statusLogic;

test('ago words', () => {
  assert.equal(ago(null), 'never');
  assert.equal(ago(new Date(Date.now() - 5000).toISOString()), '5s ago');
  assert.equal(ago(new Date(Date.now() - 125000).toISOString()), '2m ago');
  assert.equal(ago(new Date(Date.now() + 60000).toISOString()), '0s ago');
});

test('barLabel counts and times the checks', () => {
  const t0 = new Date(2026, 0, 1, 12, 0).toISOString();
  const t1 = new Date(2026, 0, 1, 12, 45).toISOString();
  const label = barLabel([{ t: t0, up: true, ms: 5 }, { t: t1, up: false, ms: null }]);
  assert.match(label, /^Last 2 checks, .*12.*00.* to .*12.*45.*: 1 up, 1 down$/);
  assert.equal(barLabel([]), 'No checks yet');
});

test('bytes uses binary units', () => {
  assert.equal(bytes(0), '0 B');
  assert.equal(bytes(1023), '1023 B');
  assert.equal(bytes(1536), '1.5 KiB');
  assert.equal(bytes(150 * 1024), '150 KiB');
  assert.equal(bytes(5 * 1024 ** 3), '5 GiB');
  assert.equal(bytes(Number.MAX_SAFE_INTEGER), '8 PiB');
});

test('duration shows the two biggest units', () => {
  assert.equal(duration(0), '0s');
  assert.equal(duration(42), '42s');
  assert.equal(duration(125), '2m 5s');
  assert.equal(duration(3700), '1h 1m');
  assert.equal(duration(93784), '1d 2h');
});

test('nodeStatPairs skips clients when unknown', () => {
  const d = {
    interfaces: { total: 3, online: 2, clients: 17, rxBytes: 2048, txBytes: 10 },
    peersHeard: { total: 1234 },
    announcesLastMinute: 12,
    uptimeSeconds: 90,
  };
  const pairs = nodeStatPairs(d).map((p) => [...p]);
  assert.deepEqual(pairs[0], ['Clients', '17']);
  assert.deepEqual(pairs.find((p) => p[0] === 'Interfaces'), ['Interfaces', '2/3 online']);
  assert.deepEqual(pairs.find((p) => p[0] === 'Traffic'), ['Traffic', '↓ 2 KiB ↑ 10 B']);
  assert.deepEqual(pairs.find((p) => p[0] === 'Peers heard'), ['Peers heard', '1,234']);
  d.interfaces.clients = null;
  assert.equal(nodeStatPairs(d).some((p) => p[0] === 'Clients'), false);
});

test('formatRate adds /s to the byte units', () => {
  assert.equal(formatRate(0), '0 B/s');
  assert.equal(formatRate(0.4), '0 B/s');
  assert.equal(formatRate(1536), '1.5 KiB/s');
});

test('niceTicks gives round steps from zero that cover the maximum', () => {
  assert.deepEqual([...niceTicks(0)], [0, 1]);
  assert.deepEqual([...niceTicks(NaN)], [0, 1]);
  assert.deepEqual([...niceTicks(Infinity)], [0, 1]);
  assert.deepEqual([...niceTicks(18)], [0, 5, 10, 15, 20]);
  for (const max of [0.3, 1, 7, 99, 1234, 5e6]) {
    const t = niceTicks(max);
    assert.equal(t[0], 0);
    assert.ok(t.at(-1) >= max, String(max));
    assert.ok(t.length >= 2 && t.length <= 7, `${max}: ${t.length}`);
  }
});

test('runs splits at gaps and drops bad values', () => {
  const r = [...runs([[1, 1], [2, 2], [3, null], [4, 4], [5, NaN], [6, 6], [7, 7]])].map((x) => [...x].map((p) => p[0]));
  assert.deepEqual(r, [[1, 2], [4], [6, 7]]);
  assert.equal(runs([]).length, 0);
  assert.equal(runs([[1, null]]).length, 0);
});

test('summarize and summaryText', () => {
  assert.equal(summarize([[1, null]]), null);
  assert.equal(summaryText([], bytes), 'no data');
  const s = summarize([[1, 2], [2, null], [3, 6]]);
  assert.deepEqual({ ...s }, { last: 6, min: 2, max: 6, avg: 4 });
  assert.equal(summaryText([[1, 1024], [2, 3072]], formatRate), 'now 3 KiB/s, average 2 KiB/s, peak 3 KiB/s');
});

test('axisTime shows the weekday except for 6 hours', () => {
  const t = new Date(2026, 0, 5, 14, 30).getTime();
  assert.match(axisTime(t, '6h'), /^14:30$/);
  assert.match(axisTime(t, '24h'), /^\w+ 14:30$/);
  assert.match(axisTime(t, '7d'), /^\w+ 14:30$/);
});

test('count formats whole numbers and small fractions', () => {
  assert.equal(count(1234), '1,234');
  assert.equal(count(2.46), '2.5');
  assert.equal(count(12.6), '13');
  assert.equal(count(NaN), '-');
});

test('peerShares gives counts and whole percents, with the rest as Other', () => {
  const rows = [...peerShares({ total: 100, lxmf: 60, nomad: 30, propagation: 5 })].map((r) => ({ ...r }));
  assert.deepEqual(rows.map((r) => [r.label, r.count, r.percent]), [['LXMF', 60, 60], ['NomadNet', 30, 30], ['Propagation', 5, 5], ['Other', 5, 5]]);
  assert.equal(peerShares({ total: 90, lxmf: 60, nomad: 30, propagation: 0 }).length, 3);
  const zero = peerShares({ total: 0, lxmf: 0, nomad: 0, propagation: 0 });
  assert.ok(zero.every((r) => r.percent === 0 && r.count === 0));
});

test('versionSummary is null unless nodes differ, and names the hosts', () => {
  const h = (host, v) => ({ host, port: 4242, stats: v === undefined ? null : { data: { rettuiVersion: v } } });
  assert.equal(versionSummary([]), null);
  assert.equal(versionSummary([h('a', '2.0.0'), h('b', '2.0.0'), h('c')]), null);
  assert.equal(versionSummary([h('a', '2.0.0'), h('b', '1.9.0'), h('c', '2.0.0'), h('d', null)]), 'Nodes run different versions: 2.0.0 (a:4242, c:4242); 1.9.0 (b:4242).');
  assert.equal(versionSummary([h('a', '__proto__'), h('b', 'constructor')]), 'Nodes run different versions: __proto__ (a:4242); constructor (b:4242).');
});

test('intervalWords says how often samples are taken', () => {
  assert.equal(intervalWords(300), '5 minutes');
  assert.equal(intervalWords(60), 'minute');
  assert.equal(intervalWords(120), '2 minutes');
  assert.equal(intervalWords(1), 'second');
  assert.equal(intervalWords(45), '45 seconds');
  assert.equal(intervalWords(undefined), 'so often');
  assert.equal(intervalWords(0), 'so often');
});

test('nearestIndex picks the closest time and clamps at the ends', () => {
  const t = [100, 200, 400, 1000];
  assert.equal(nearestIndex(t, 100), 0);
  assert.equal(nearestIndex(t, 149), 0);
  assert.equal(nearestIndex(t, 150), 0);
  assert.equal(nearestIndex(t, 151), 1);
  assert.equal(nearestIndex(t, 290), 1);
  assert.equal(nearestIndex(t, 310), 2);
  assert.equal(nearestIndex(t, 800), 3);
  assert.equal(nearestIndex(t, -50), 0);
  assert.equal(nearestIndex(t, 99999), 3);
  assert.equal(nearestIndex([5], 77), 0);
  assert.equal(nearestIndex([], 5), -1);
  assert.equal(nearestIndex(t, NaN), -1);
  assert.equal(nearestIndex(t, undefined), -1);
});

test('timeAt maps a pixel to a time inside the window', () => {
  assert.equal(timeAt(50, 50, 100, 1000, 2000), 1000);
  assert.equal(timeAt(100, 50, 100, 1000, 2000), 1500);
  assert.equal(timeAt(0, 50, 100, 1000, 2000), 1000);
  assert.equal(timeAt(999, 50, 100, 1000, 2000), 2000);
  assert.equal(timeAt(70, 50, 0, 1000, 2000), 1000);
});

test('tooltipRows has one row per line and says no data for gaps', () => {
  const lines = [
    { label: 'In', cls: 'c1', points: [[1, 1024], [2, null], [3, 2048]] },
    { label: 'Out', cls: 'c3 d1', points: [[1, 5], [2, 6]] },
  ];
  const at = (i) => [...tooltipRows(lines, i, formatRate)].map((r) => ({ ...r }));
  assert.deepEqual(at(0), [{ label: 'In', cls: 'c1', text: '1 KiB/s' }, { label: 'Out', cls: 'c3 d1', text: '5 B/s' }]);
  assert.deepEqual(at(1).map((r) => r.text), ['no data', '6 B/s']);
  assert.deepEqual(at(2).map((r) => r.text), ['2 KiB/s', 'no data']);
  assert.deepEqual(at(-1).map((r) => r.text), ['no data', 'no data']);
  assert.deepEqual(at(9).map((r) => r.text), ['no data', 'no data']);
  assert.equal(tooltipRows([], 0, formatRate).length, 0);
});

test('tooltipTitle has weekday, date and 24 hour time; tooltipSpeech joins the rows', () => {
  const title = tooltipTitle(new Date(2026, 10, 19, 6, 28).getTime());
  assert.match(title, /Thu/);
  assert.match(title, /2026/);
  assert.match(title, /06:28/);
  assert.equal(tooltipSpeech('T', [{ label: 'In', text: '1 KiB/s' }, { label: 'Out', text: 'no data' }]), 'T: In 1 KiB/s, Out no data');
});

test('tooltipPosition goes right of the anchor, flips near the right edge and stays inside', () => {
  const pos = (...a) => ({ ...tooltipPosition(...a) });
  assert.deepEqual(pos(100, 80, 120, 60, 400, 150), { x: 112, y: 50 });
  assert.deepEqual(pos(350, 80, 120, 60, 400, 150), { x: 218, y: 50 });
  assert.deepEqual(pos(10, 5, 120, 60, 400, 150), { x: 22, y: 0 });
  assert.deepEqual(pos(10, 149, 120, 60, 400, 150), { x: 22, y: 90 });
  // Too narrow to fit on either side: pinned to the left edge.
  assert.deepEqual(pos(100, 80, 300, 60, 250, 150), { x: 0, y: 50 });
  assert.deepEqual(pos(100, 80, 300, 200, 250, 150), { x: 0, y: 0 });
});

test('runs also splits where samples are missing, and gapLimit is three usual steps', () => {
  const pts = [[0, 1], [10, 1], [20, 1], [30, 1], [100, 1], [110, 1]];
  assert.equal(gapLimit(pts), 30);
  assert.deepEqual([...runs(pts, gapLimit(pts))].map((r) => [...r].map((p) => p[0])), [[0, 10, 20, 30], [100, 110]]);
  assert.equal(runs(pts).length, 1);
  assert.equal(gapLimit([[0, 1], [5, 1]]), 0);
  assert.equal(gapLimit([]), 0);
});

const H = (host, o = {}) => ({ host, port: 4242, name: null, role: 'node', proxy: null, proxiedBy: null, group: null, ...o });

test('names and badges', () => {
  const hosts = [H('a.test', { role: 'proxy', name: 'Door', proxy: { for: ['b.test:4242', 'c.test:4242'] } }), H('b.test', { proxiedBy: 'a.test:4242' }), H('c.test')];
  assert.equal(hostKey(hosts[0]), 'a.test:4242');
  assert.equal(displayName(hosts[0]), 'Door');
  assert.equal(displayName(hosts[1]), 'b.test:4242');
  assert.equal(showBadges(hosts), true);
  assert.equal(showBadges([H('x'), H('y')]), false);
  assert.equal(showBadges([]), false);
  assert.deepEqual([badgeText(hosts[0]), badgeText(hosts[1])], ['Proxy', 'RNS node']);
  assert.equal(badgeTitle(hosts[0], hosts), 'Proxy for 2 nodes');
  assert.equal(badgeTitle(H('p', { role: 'proxy', proxy: { for: ['x:1'] } }), []), 'Proxy for 1 node');
  assert.equal(badgeTitle(hosts[1], hosts), 'RNS node, behind the proxy Door');
  assert.equal(badgeTitle(H('q', { proxiedBy: 'gone:1' }), hosts), 'RNS node, behind the proxy gone:1');
  assert.equal(badgeTitle(hosts[2], hosts), 'RNS node');
});

test('groupHosts nests members under their proxy, in the proxy order', () => {
  const hosts = [H('b.test'), H('a.test', { role: 'proxy', proxy: { for: ['c.test:4242', 'b.test:4242', 'missing:1'] } }), H('c.test', { proxiedBy: 'a.test:4242' }), H('d.test')];
  hosts[0].proxiedBy = 'a.test:4242';
  const g = [...groupHosts(hosts)].map((x) => [x.h.host, [...x.members].map((m) => m.host)]);
  assert.deepEqual(g, [['a.test', ['c.test', 'b.test']], ['d.test', []]]);
  assert.equal(groupHosts([]).length, 0);
  // A node whose proxy is not listed still shows.
  assert.deepEqual([...groupHosts([H('x', { proxiedBy: 'nope:1' })])].map((x) => x.h.host), ['x']);
});

test('peerRange, groupCoverage and groupPairs', () => {
  assert.equal(peerRange(5, 5), '5');
  assert.equal(peerRange(1200, 3400), '1,200\u20133,400');
  assert.equal(groupCoverage({ reporting: 3, nodes: 3, partial: false, missing: [] }), '3 of 3 nodes reporting');
  assert.equal(groupCoverage({ reporting: 1, nodes: 3, partial: true, missing: ['a:1', 'b:1'] }, { 'a:1': 'Alpha' }), '1 of 3 nodes reporting (not: Alpha, b:1)');
  assert.equal(groupPairs(null).length, 0);
  assert.equal(groupPairs({ data: null }).length, 0);
  const g = { data: { interfaces: { total: 5, online: 4, clients: 15, rxBytes: 2048, txBytes: 10 }, announcesLastMinute: 12, peersHeard: { sum: { total: 350 }, max: { total: 250 } } } };
  const pairs = [...groupPairs(g)].map((p) => [...p]);
  assert.deepEqual(pairs, [['Clients', '15'], ['Interfaces', '4/5 online'], ['Traffic', '\u2193 2 KiB \u2191 10 B'], ['Peers heard', '250\u2013350'], ['Announces', '12/min']]);
  g.data.interfaces.clients = null;
  assert.equal(groupPairs(g).some((p) => p[0] === 'Clients'), false);
});

test('peerRangeRows give ranges per kind and the rest as Other', () => {
  const rows = [...peerRangeRows({ sum: { total: 100, lxmf: 60, nomad: 30, propagation: 5 }, max: { total: 70, lxmf: 40, nomad: 30, propagation: 5 } })].map((r) => ({ ...r }));
  assert.deepEqual(rows.map((r) => [r.label, r.text, r.count, r.percent]), [['LXMF', '40\u201360', 60, 60], ['NomadNet', '30', 30, 30], ['Propagation', '5', 5, 5], ['Other', '5', 5, 5]]);
  const zero = [...peerRangeRows({ sum: { total: 0, lxmf: 0, nomad: 0, propagation: 0 }, max: { total: 0, lxmf: 0, nomad: 0, propagation: 0 } })];
  assert.equal(zero.length, 3);
  assert.ok(zero.every((r) => r.percent === 0));
});

test('exact group peers show plain numbers, with a de-duplicated note', () => {
  const peers = { exact: true, union: { total: 100, lxmf: 60, nomad: 30, propagation: 5 }, sum: { total: 150 }, max: { total: 90 }, lists: { have: 2, of: 2 } };
  const g = { data: { interfaces: { total: 1, online: 1, clients: 1, rxBytes: 0, txBytes: 0 }, announcesLastMinute: 0, peersHeard: peers } };
  assert.deepEqual([...[...groupPairs(g)].find((p) => p[0] === 'Peers heard')], ['Peers heard', '100 (de-duplicated)']);
  const rows = [...peerRangeRows(peers)].map((r) => [r.label, r.text, r.percent]);
  assert.deepEqual(rows, [['LXMF', '60', 60], ['NomadNet', '30', 30], ['Propagation', '5', 5], ['Other', '5', 5]]);
  assert.match(peerNote(peers), /de-duplicated/);
});

test('peerNote for a range says how many nodes had lists', () => {
  const base = { exact: false, union: null, sum: {}, max: {} };
  assert.match(peerNote({ ...base, lists: { have: 0, of: 3 } }), /cannot be removed/);
  assert.doesNotMatch(peerNote({ ...base, lists: { have: 0, of: 3 } }), /supplied a peer list/);
  assert.match(peerNote({ ...base, lists: { have: 2, of: 3 } }), /2 of 3 reporting nodes supplied a peer list/);
});
