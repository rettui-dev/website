import test from 'node:test';
import assert from 'node:assert/strict';

test('the tests run on Node.js 24.7 or later', () => {
  const [major, minor] = process.versions.node.split('.').map(Number);
  assert.ok(major > 24 || (major === 24 && minor >= 7), `Node.js 24.7 or later is needed, this is ${process.versions.node}; other failures here come from that`);
});
