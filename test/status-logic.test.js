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
  hostKey, displayName, summaryFacts, lastUp, downText, staleNote, warnings, backlogAbnormal, networkFacts, storeFacts, diskFacts, groupFacts, partialNote, groupWarning, badgeText, badgeTitle, groupHosts, peerRange, peerNote, groupCoverage, groupPairs, peerRangeRows,
  percentText, propagationPairs, diskPairs, diskUsedPercent, groupStoragePairs, groupPropagationPairs, groupDiskPairs,
  gapLimit, nearestIndex, timeAt, tooltipTitle, tooltipRows, tooltipSpeech, tooltipPosition } =
  sandbox.statusLogic;
const { dayLevel, dayDate, dayTitle, uptimeLabel, incidentSpan } = sandbox.statusLogic;

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
  // Only proxies carry a badge; ordinary nodes have none.
  assert.deepEqual([badgeText(hosts[0]), badgeText(hosts[1]), badgeText(hosts[2])], ['Proxy', null, null]);
  assert.equal(badgeTitle(hosts[0], hosts), 'Proxy for 2 nodes');
  assert.equal(badgeTitle(H('p', { role: 'proxy', proxy: { for: ['x:1'] } }), []), 'Proxy for 1 node');
  assert.equal(badgeTitle(hosts[1], hosts), null);
});

const D = (o = {}) => ({
  interfaces: { total: 2, online: 2, clients: 23, rxBytes: 2048, txBytes: 10 }, announcesLastMinute: 3, uptimeSeconds: 3600,
  peersHeard: { total: 1300 }, propagation: null, disk: null, ...o,
});
const R = (o = {}) => ({ host: 'n.test', port: 4242, status: 'up', uptimePercent: 100, latencyMs: 12, error: null, history: [], stats: { stale: false, fetchedAt: new Date().toISOString(), data: D() }, ...o });

test('summaryFacts is at most four short facts and leaves out the unknown', () => {
  assert.deepEqual([...summaryFacts(R())].map((f) => [...f]), [['Clients', '23'], ['Peers heard', '1,300'], ['Up', '100% over 24 h']]);
  const noClients = R({ uptimePercent: null, stats: { data: D({ interfaces: { total: 1, online: 1, clients: null, rxBytes: 0, txBytes: 0 } }) } });
  assert.deepEqual([...summaryFacts(noClients)].map((f) => [...f]), [['Peers heard', '1,300']]);
  // Without stats the connect time is in the line, as there is nothing else to open.
  assert.deepEqual([...summaryFacts(R({ stats: null, uptimePercent: null }))].map((f) => [...f]), [['Connect time', '12 ms']]);
  assert.equal(summaryFacts(R({ stats: null, uptimePercent: null, latencyMs: null })).length, 0);
});

test('warnings say nothing when all is well and name the level when not', () => {
  assert.equal(warnings(R()).length, 0);
  assert.equal(warnings(R({ stats: null })).length, 0);
  const w = (disk, propagation, stale = false) => [...warnings(R({ stats: { stale, data: D({ disk, propagation }) } }))].map((x) => ({ ...x }));
  assert.deepEqual(w({ level: 'ok', usedPercent: 50 }, null), []);
  assert.deepEqual(w({ level: 'high', usedPercent: 85 }, null), [{ kind: 'high', text: 'Disk about 85% used' }]);
  assert.deepEqual(w({ level: 'full', usedPercent: 95 }, null), [{ kind: 'full', text: 'Disk about 95% used, almost full' }]);
  // Exactly half alive is fine; fewer is not.
  assert.deepEqual(w(null, { peersAlive: 4, peersTotal: 8, unhandledMessages: 0 }), []);
  assert.deepEqual(w(null, { peersAlive: 3, peersTotal: 8, unhandledMessages: 0 }), [{ kind: 'high', text: 'Peered 3/8 alive' }]);
  // A backlog alone is normal: no warning, however large, while it fits stored messages x peers.
  assert.deepEqual(w(null, { unhandledMessages: 28 }), []);
  assert.deepEqual(w(null, { storedMessages: 100, peersAlive: 3, peersTotal: 3, unhandledMessages: 300 }), []);
  assert.deepEqual(w(null, { storedMessages: 0, peersAlive: 0, peersTotal: 0, unhandledMessages: 0 }), []);
  // More waiting than the store and the peers can explain is abnormal.
  assert.deepEqual(w(null, { storedMessages: 100, peersAlive: 3, peersTotal: 3, unhandledMessages: 301 }), [{ kind: 'high', title: 'Messages stored on this node that it still has to offer to its peer nodes, counted once for each peer. High right after peering starts and should fall as peers catch up.', text: 'Waiting to send to peers: 301 messages, more than the store and peers explain' }]);
  assert.deepEqual(w(null, { storedMessages: 5, peersAlive: 0, peersTotal: 0, unhandledMessages: 1 }), [{ kind: 'high', title: 'Messages stored on this node that it still has to offer to its peer nodes, counted once for each peer. High right after peering starts and should fall as peers catch up.', text: 'Waiting to send to peers: 1 message, more than the store and peers explain' }]);
  assert.equal(backlogAbnormal(null), false);
  assert.equal(backlogAbnormal({ storedMessages: 1, peersTotal: 1, unhandledMessages: 1 }), false);
  assert.equal(backlogAbnormal({ storedMessages: 1, peersTotal: 1, unhandledMessages: 2 }), true);
  // Exact figures need no "about".
  assert.deepEqual(w({ level: 'high', usedPercent: 81, fsFreeBytes: 19, fsTotalBytes: 100 }, null), [{ kind: 'high', text: 'Disk 81% used' }]);
  // Old numbers are not warned about.
  assert.deepEqual(w({ level: 'full', usedPercent: 95 }, null, true), []);
});

test('downText, staleNote and lastUp', () => {
  const t = Date.now() - 14 * 60000;
  const h = R({ status: 'down', error: 'timed out', history: [{ t: t - 1000, up: true, ms: 5 }, { t, up: false }] });
  assert.equal(lastUp(h), new Date(t - 1000).toISOString());
  assert.match(downText(h), /^Connection failed: timed out\. Last up 1[45]m ago\.$/);
  assert.equal(downText(R({ status: 'down', error: null, history: [] })), 'Connection failed. No successful check lately.');
  assert.equal(staleNote({ stale: false, fetchedAt: 'x' }), null);
  assert.equal(staleNote(null), null);
  assert.match(staleNote({ stale: true, fetchedAt: new Date(Date.now() - 12 * 60000).toISOString() }), /^Stats from 12m ago \(last fetch failed\)$/);
});

test('networkFacts, storeFacts and diskFacts leave out what is not known', () => {
  const n = [...networkFacts(R())].map((f) => [...f]);
  assert.deepEqual(n.map((f) => f[0]), ['Interfaces', 'Traffic since start', 'Announces', 'Node running', 'Connect time']);
  assert.deepEqual([...networkFacts(R({ stats: null, latencyMs: null }))], []);
  // The number and its unit never part at a line break.
  assert.equal(n[1][1], 'In\u00a02\u00a0KiB, out\u00a010\u00a0B');
  assert.deepEqual([...networkFacts(R({ stats: null }))], []);
  assert.deepEqual([...storeFacts(null)], []);
  assert.deepEqual([...storeFacts(PROP)].map((f) => [...f]), [
    ['Stored', '1,234 messages, 5 MiB of 50 MiB (10%)'], ['Peered', '5 of 8 alive'], ['Waiting to send to peers', '7'],
  ]);
  assert.deepEqual([...diskFacts(null)], []);
  assert.deepEqual([...diskFacts({ usedPercent: 85, level: 'high' })].map((f) => [...f]), [['Disk', 'about 85% used']]);
  assert.deepEqual([...diskFacts({ usedPercent: 60, level: 'ok', fsFreeBytes: 40 * 1024, fsTotalBytes: 100 * 1024 })].map((f) => [...f]), [['Disk', '60% used'], ['Free', '40 KiB of 100 KiB']]);
  assert.equal(diskFacts({ usedPercent: 95, level: 'full' })[0][1], 'about 95% used, almost full');
});

test('groupFacts, partialNote and groupWarning', () => {
  const ms = [R(), R({ host: 'm.test', status: 'down' })];
  const g = { nodes: 2, reporting: 1, partial: true, missing: ['m.test:4242'], data: { interfaces: { clients: 34 }, announcesLastMinute: 33,
    peersHeard: { exact: false, sum: { total: 3300 }, max: { total: 1300 } }, disk: { worst: { level: 'high', usedPercent: 80, node: 'm.test:4242' }, lowestFree: null } } };
  assert.deepEqual([...groupFacts({ group: g }, ms)], ['1 of 2 nodes up', '34 clients', '1,300\u00a0to\u00a03,300 peers heard', '33 announces/min']);
  g.data.peersHeard = { exact: true, union: { total: 2000 } };
  assert.equal(groupFacts({ group: g }, ms)[2], '2,000 peers heard');
  assert.deepEqual([...groupFacts({ group: null }, ms)], ['1 of 2 nodes up']);
  assert.equal(partialNote(g, { 'm.test:4242': 'Mine' }), '1 of 2 nodes reporting. Not reporting: Mine');
  assert.equal(partialNote({ partial: false }, {}), null);
  assert.deepEqual({ ...groupWarning(g, { 'm.test:4242': 'Mine' }) }, { kind: 'high', text: 'Fullest disk: Mine about 80% used' });
  g.data.disk.worst.level = 'ok';
  assert.equal(groupWarning(g, {}), null);
  assert.equal(groupWarning(null, {}), null);
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
  assert.equal(peerRange(1200, 3400), '1,200\u00a0to\u00a03,400');
  assert.equal(groupCoverage({ reporting: 3, nodes: 3, partial: false, missing: [] }), '3 of 3 nodes reporting');
  assert.equal(groupCoverage({ reporting: 1, nodes: 3, partial: true, missing: ['a:1', 'b:1'] }, { 'a:1': 'Alpha' }), '1 of 3 nodes reporting (not: Alpha, b:1)');
  assert.equal(groupPairs(null).length, 0);
  assert.equal(groupPairs({ data: null }).length, 0);
  const g = { data: { interfaces: { total: 5, online: 4, clients: 15, rxBytes: 2048, txBytes: 10 }, announcesLastMinute: 12, peersHeard: { sum: { total: 350 }, max: { total: 250 } } } };
  const pairs = [...groupPairs(g)].map((p) => [...p]);
  assert.deepEqual(pairs, [['Clients', '15'], ['Interfaces', '4/5 online'], ['Traffic', '\u2193 2 KiB \u2191 10 B'], ['Peers heard', '250\u00a0to\u00a0350'], ['Announces', '12/min']]);
  g.data.interfaces.clients = null;
  assert.equal(groupPairs(g).some((p) => p[0] === 'Clients'), false);
});

test('peerRangeRows give ranges per kind and the rest as Other', () => {
  const rows = [...peerRangeRows({ sum: { total: 100, lxmf: 60, nomad: 30, propagation: 5 }, max: { total: 70, lxmf: 40, nomad: 30, propagation: 5 } })].map((r) => ({ ...r }));
  assert.deepEqual(rows.map((r) => [r.label, r.text, r.count, r.percent]), [['LXMF', '40\u00a0to\u00a060', 60, 60], ['NomadNet', '30', 30, 30], ['Propagation', '5', 5, 5], ['Other', '5', 5, 5]]);
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

const PROP = {
  enabled: true, storedMessages: 1234, storedBytes: 5 * 1024 * 1024, storageLimitBytes: 50 * 1024 * 1024, peersConnected: 2, peersTotal: 8, peersAlive: 5, peersStatic: 3, peersAuto: 5,
  peerLimit: 20, autopeer: true, autopeerDepth: 4, messagesSentToPeers: 1000, messagesReceivedFromPeers: 2000, unhandledMessages: 7,
};

test('percentText', () => {
  assert.equal(percentText(5, 10), '50%');
  assert.equal(percentText(1, 40), '2.5%');
  assert.equal(percentText(0, 40), '0%');
  assert.equal(percentText(1, 0), null);
  assert.equal(percentText(null, 10), null);
  assert.equal(percentText(undefined, 10), null);
});

test('propagationPairs lists what the node sent and skips the rest', () => {
  const pairs = [...propagationPairs(PROP)].map((p) => [...p]);
  assert.deepEqual(pairs, [
    ['Stored', '1,234 messages, 5 MiB (10% of 50 MiB)'],
    ['Peered nodes', '5/8 alive (3 static, 5 auto), limit 20'],
    ['Auto-peering', 'on (depth 4)'],
    ['Peer traffic', '↑ 1,000 sent ↓ 2,000 received'],
    ['Waiting to send to peers', '7'],
  ]);
  assert.equal(propagationPairs(null).length, 0);
  assert.equal(propagationPairs({}).length, 0);
  const sparse = [...propagationPairs({ storedMessages: 1, storedBytes: null, peersAlive: 2, autopeer: false })].map((p) => [...p]);
  assert.deepEqual(sparse, [['Stored', '1 message'], ['Peered nodes', '2/? alive'], ['Auto-peering', 'off']]);
  assert.deepEqual([...propagationPairs({ storedBytes: 2048 })].map((p) => [...p]), [['Stored', '2 KiB']]);
});

test('diskPairs and diskUsedPercent', () => {
  const d = { dataBytes: 2048, fsTotalBytes: 100 * 1024, fsFreeBytes: 40 * 1024 };
  assert.deepEqual([...diskPairs(d)].map((p) => [...p]), [['Data size', '2 KiB'], ['Free', '40 KiB of 100 KiB']]);
  assert.equal(diskUsedPercent(d), 60);
  assert.equal(diskUsedPercent({ dataBytes: 1, fsTotalBytes: null, fsFreeBytes: null }), null);
  assert.equal(diskUsedPercent({ fsTotalBytes: 0, fsFreeBytes: 0 }), null);
  assert.equal(diskUsedPercent({ fsTotalBytes: 10, fsFreeBytes: 50 }), 0);
  assert.equal(diskUsedPercent(null), null);
  assert.equal(diskPairs(null).length, 0);
  assert.deepEqual([...diskPairs({ dataBytes: 5, fsTotalBytes: null, fsFreeBytes: null })].map((p) => [...p]), [['Data size', '5 B']]);
});

test('groupStoragePairs shows sums and the disk with the least free share', () => {
  const g = { data: { propagation: { ...PROP, nodes: 2 }, disk: { nodes: 2, dataBytes: 4096, lowestFree: { percent: 12.5, freeBytes: 1024, totalBytes: 8192, node: 'a' } } } };
  const pairs = [...groupStoragePairs(g)].map((p) => [...p]);
  assert.equal(pairs[0][0], 'Stored');
  assert.deepEqual(pairs.slice(-2), [['Data size', '4 KiB'], ['Least disk free', '12.5% (1 KiB of 8 KiB)']]);
  assert.equal(groupStoragePairs({ data: {} }).length, 0);
  assert.equal(groupStoragePairs(null).length, 0);
});

test('group storage is split into the message store and the disk', () => {
  const g = { data: { propagation: { ...PROP, nodes: 2 }, disk: { nodes: 2, dataBytes: 4096, worst: { level: 'high', usedPercent: 80, node: 'a' }, lowestFree: null } } };
  assert.equal(groupPropagationPairs(g)[0][0], 'Stored');
  assert.deepEqual([...groupDiskPairs(g)].map((p) => [...p]), [['Data size', '4 KiB'], ['Fullest disk', '80% used']]);
  assert.equal(groupPropagationPairs({ data: { disk: g.data.disk } }).length, 0);
  assert.equal(groupDiskPairs({ data: {} }).length, 0);
  assert.equal(groupDiskPairs(null).length, 0);
});

test('locked sections: which a row offers a login for, and the words for them', () => {
  const { rowLocks, lockText, detailsLocked } = sandbox.statusLogic;
  const all = ['details', 'storage', 'peers', 'disk', 'versions'];
  assert.deepEqual([...rowLocks({ locked: all, stats: { ok: true } })], ['storage', 'peers', 'disk', 'versions']);
  assert.deepEqual([...rowLocks({ locked: all, stats: null, group: null })], [], 'nothing to see without stats');
  assert.deepEqual([...rowLocks({ locked: all, stats: null, group: { nodes: 2 } })], ['storage', 'peers', 'disk', 'versions']);
  assert.deepEqual([...rowLocks({ locked: [], stats: { ok: true } })], []);
  assert.deepEqual([...rowLocks({ stats: { ok: true } })], [], 'no users: no locks');
  assert.equal(lockText(['storage', 'peers', 'disk', 'versions']), 'Message store, peered nodes, disk and versions need a login.');
  assert.equal(lockText(['details', 'disk']), 'Disk needs a login.');
  assert.equal(lockText(['storage']), 'Message store needs a login.');
  assert.equal(lockText(['versions']), 'Versions need a login.');
  assert.equal(lockText(['peers', 'disk']), 'Peered nodes and disk need a login.');
  assert.equal(lockText(['details']), null);
  assert.equal(lockText(undefined), null);
  assert.equal(detailsLocked({ locked: ['details'] }), true);
  assert.equal(detailsLocked({ locked: ['disk'] }), false);
  assert.equal(detailsLocked({}), false);
});

test('day cells are told apart by level, with no data kept apart from zero', () => {
  assert.equal(dayLevel(100), 'ok');
  assert.equal(dayLevel(99.9), 'ok');
  assert.equal(dayLevel(99.8), 'warn');
  assert.equal(dayLevel(95), 'warn');
  assert.equal(dayLevel(94.9), 'bad');
  assert.equal(dayLevel(0), 'bad');
  for (const v of [null, undefined, NaN, 'x', Infinity]) assert.equal(dayLevel(v), 'none');
});

test('day titles name the UTC date and the percent', () => {
  const now = Date.UTC(2026, 10, 19, 23, 59);
  assert.equal(dayDate(89, 90, now), '2026-11-19');
  assert.equal(dayDate(88, 90, now), '2026-11-18');
  assert.equal(dayDate(0, 90, now), '2026-08-22');
  assert.equal(dayTitle(89, 90, 99.5, now), '2026-11-19: 99.5% up');
  assert.equal(dayTitle(5, 90, null, now), '2026-08-27: no data');
});

test('the uptime bar has a text alternative with the same facts', () => {
  const days = new Array(90).fill(null);
  days[89] = 100;
  days[88] = 97.2;
  days[87] = 80;
  days[86] = 99.9;
  const label = uptimeLabel({ days, uptime90: { percent30: 99.1, percent90: 98.7 } });
  assert.equal(label, 'Uptime over the last 90 days: 98.7%, over the last 30 days: 99.1%. 2 days below 99.9%, 86 without data');
  assert.equal(uptimeLabel({ days: new Array(90).fill(null), uptime90: { percent30: null, percent90: null } }), 'Uptime over the last 90 days: no data yet');
  assert.equal(uptimeLabel({}), 'Uptime over the last 90 days: no data yet');
  assert.match(uptimeLabel({ days: [100, 50], uptime90: { percent30: 75, percent90: 75 } }), /1 day below 99.9%, 0 without data/);
});

test('incident spans say ongoing or lasted', () => {
  assert.equal(incidentSpan({ ongoing: true, seconds: 750 }), 'Down for 12m 30s so far');
  assert.equal(incidentSpan({ ongoing: false, seconds: 3700 }), 'Lasted 1h 1m');
});
