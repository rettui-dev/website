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
const { ago, barLabel, bytes, duration, nodeStatPairs } = sandbox.statusLogic;

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
