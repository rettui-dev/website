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
const { ago, barLabel, bytes, duration, nodeStatPairs, formatRate, niceTicks, runs, summarize, summaryText, axisTime, peerShares, versionSummary, count, intervalWords } =
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
