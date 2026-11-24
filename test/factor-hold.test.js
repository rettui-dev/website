// The waits after a first second factor (lib/factor-hold.js): kept in memory at once, written to
// second-factor-holds.json, read back at start, dropped when over, bounded, and a file that cannot
// be read is said and treated as empty.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { FIRST_FACTOR_HOLD_MS, HOLDS_FILE, MAX_HOLDS, createFactorHolds } from '../lib/factor-hold.js';

const NOW = 1_800_000_000_000;
const dir = () => fs.mkdtemp(path.join(os.tmpdir(), 'factor-hold-'));

test('a wait starts at once, runs 24 hours, is written privately and read back at the next start', async () => {
  const dataDir = await dir();
  const clock = { t: NOW };
  const holds = createFactorHolds({ dataDir, now: () => clock.t });
  assert.equal(holds.until('bob'), null);
  const pending = holds.start('Bob');
  // In memory before the write is done.
  assert.equal(holds.until('bob'), NOW + FIRST_FACTOR_HOLD_MS);
  assert.equal(await pending, NOW + FIRST_FACTOR_HOLD_MS);
  assert.equal(holds.file, path.join(dataDir, HOLDS_FILE));
  if (process.platform !== 'win32') assert.equal((await fs.stat(holds.file)).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(await fs.readFile(holds.file, 'utf8')), { version: 1, holds: { bob: new Date(NOW + FIRST_FACTOR_HOLD_MS).toISOString() } });
  // No temporary file is left.
  assert.deepEqual(await fs.readdir(dataDir), [HOLDS_FILE]);
  const next = createFactorHolds({ dataDir, now: () => clock.t });
  await next.load();
  assert.equal(next.until('BOB'), NOW + FIRST_FACTOR_HOLD_MS);
  clock.t += FIRST_FACTOR_HOLD_MS - 1;
  assert.equal(next.until('bob'), NOW + FIRST_FACTOR_HOLD_MS);
  clock.t += 1;
  assert.equal(next.until('bob'), null, 'over');
  // A wait that is over is not read back.
  const later = createFactorHolds({ dataDir, now: () => clock.t });
  await later.load();
  assert.equal(later.until('bob'), null);
});

test('starting again moves the wait; other users are not touched', async () => {
  const clock = { t: NOW };
  const holds = createFactorHolds({ now: () => clock.t });
  await holds.start('a');
  clock.t += 3600_000;
  await holds.start('b');
  await holds.start('a');
  assert.equal(holds.until('a'), clock.t + FIRST_FACTOR_HOLD_MS);
  assert.equal(holds.until('b'), clock.t + FIRST_FACTOR_HOLD_MS);
  assert.equal(holds.until('c'), null);
  // Without a data directory nothing is written.
  assert.equal(holds.file, null);
  await holds.load();
  assert.equal(holds.until('a'), clock.t + FIRST_FACTOR_HOLD_MS);
});

test('a file that is there but cannot be used is moved aside, said once, and the waits start empty', async () => {
  const aside = `${HOLDS_FILE}.unreadable-${new Date(NOW).toISOString().replace(/[:.]/g, '-')}`;
  const cases = [
    ['not json', '{', /is not valid JSON, so it was moved to /],
    ['a directory', null, /cannot be read \(it is not a small file\), so it was moved to /],
    ['too large', 'x'.repeat(1024 * 1024 + 1), /cannot be read/],
    ['another version', JSON.stringify({ version: 2, holds: { bob: new Date(NOW + 1000).toISOString() } }), /is not of the form this version writes/],
    ['not a map', JSON.stringify({ version: 1, holds: [] }), /is not of the form this version writes/],
  ];
  for (const [name, text] of cases) {
    const dataDir = await dir();
    if (text === null) await fs.mkdir(path.join(dataDir, HOLDS_FILE));
    else await fs.writeFile(path.join(dataDir, HOLDS_FILE), text);
    const logs = [];
    const holds = createFactorHolds({ dataDir, now: () => NOW, log: (m) => logs.push(m) });
    await holds.load();
    assert.equal(logs.length, 1, name);
    assert.match(logs[0], cases.find((c) => c[0] === name)[2], name);
    assert.ok(logs[0].includes(aside), name);
    assert.equal(holds.until('bob'), null, name);
    // The old file is kept as it was, under the new name; the next write makes a new one.
    if (text !== null) assert.equal(await fs.readFile(path.join(dataDir, aside), 'utf8'), text, name);
    await holds.start('carol');
    assert.equal(JSON.parse(await fs.readFile(path.join(dataDir, HOLDS_FILE), 'utf8')).holds.carol, new Date(NOW + FIRST_FACTOR_HOLD_MS).toISOString(), name);
  }
});

test('an unusable file that cannot be moved aside is never written over', async () => {
  const dataDir = await dir();
  const aside = `${HOLDS_FILE}.unreadable-${new Date(NOW).toISOString().replace(/[:.]/g, '-')}`;
  await fs.writeFile(path.join(dataDir, HOLDS_FILE), '{');
  // A directory with something in it where the file would go: the rename fails.
  await fs.mkdir(path.join(dataDir, aside));
  await fs.writeFile(path.join(dataDir, aside, 'x'), '');
  const logs = [];
  const holds = createFactorHolds({ dataDir, now: () => NOW, log: (m) => logs.push(m) });
  await holds.load();
  assert.equal(logs.length, 1);
  assert.match(logs[0], /could not be moved aside .* not written over/);
  await holds.start('bob');
  assert.equal(holds.until('bob'), NOW + FIRST_FACTOR_HOLD_MS, 'kept in memory');
  assert.equal(await fs.readFile(path.join(dataDir, HOLDS_FILE), 'utf8'), '{');
});

test('bad entries are left out; a time further off than a wait is cut down to one, never dropped', async () => {
  const dataDir = await dir();
  const iso = (ms) => new Date(ms).toISOString();
  await fs.writeFile(path.join(dataDir, HOLDS_FILE), JSON.stringify({ version: 1, holds: { bob: iso(NOW + 1000), '../x': iso(NOW + 1000), 'Upper': iso(NOW + 1000), eve: 'soon', mal: 5, far: iso(NOW + 2 * FIRST_FACTOR_HOLD_MS), old: iso(NOW - 1) } }));
  const logs = [];
  const holds = createFactorHolds({ dataDir, now: () => NOW, log: (m) => logs.push(m) });
  await holds.load();
  assert.deepEqual(logs, []);
  assert.equal(holds.until('bob'), NOW + 1000);
  assert.equal(holds.until('far'), NOW + FIRST_FACTOR_HOLD_MS);
  for (const name of ['../x', 'upper', 'eve', 'mal', 'old']) assert.equal(holds.until(name), null, name);
});

test('moving the clock back does not end a wait', async () => {
  const clock = { t: NOW };
  const holds = createFactorHolds({ now: () => clock.t });
  await holds.start('bob');
  clock.t -= 1000;
  assert.equal(holds.until('bob'), clock.t + FIRST_FACTOR_HOLD_MS, 'cut down to a full wait from now');
  clock.t -= 7 * 24 * 3600_000;
  await holds.start('carol');
  assert.equal(holds.until('bob'), clock.t + FIRST_FACTOR_HOLD_MS, 'still there after a prune');
  clock.t += FIRST_FACTOR_HOLD_MS;
  assert.equal(holds.until('bob'), null);
});

test('a write that fails is said, and the wait holds in memory all the same', async () => {
  const dataDir = await dir();
  // The data directory is a file: nothing can be written in it.
  const file = path.join(dataDir, 'plain');
  await fs.writeFile(file, '');
  const logs = [];
  const holds = createFactorHolds({ dataDir: file, now: () => NOW, log: (m) => logs.push(m) });
  assert.equal(await holds.start('bob'), NOW + FIRST_FACTOR_HOLD_MS);
  assert.equal(logs.length, 1);
  assert.match(logs[0], /could not save second-factor-holds\.json/);
  assert.equal(holds.until('bob'), NOW + FIRST_FACTOR_HOLD_MS);
});

test('at most MAX_HOLDS waits are kept; the oldest goes first', async () => {
  const clock = { t: NOW };
  const holds = createFactorHolds({ now: () => clock.t });
  for (let i = 0; i < MAX_HOLDS + 1; i++) await holds.start(`u${i}`);
  assert.equal(holds.until('u0'), null);
  assert.equal(holds.until('u1'), NOW + FIRST_FACTOR_HOLD_MS);
  assert.equal(holds.until(`u${MAX_HOLDS}`), NOW + FIRST_FACTOR_HOLD_MS);
});
