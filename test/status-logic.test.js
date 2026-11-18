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
const { ago, barLabel } = sandbox.statusLogic;

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
