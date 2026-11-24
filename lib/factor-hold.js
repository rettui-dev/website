// The wait after a first second factor: a user who turns on two-step sign-in on the website while
// they had no second factor (the app code, or their first passkey) cannot change anything on a node
// for FIRST_FACTOR_HOLD_MS. Such a first factor is confirmed by the password alone, so without the
// wait, a stolen password would be enough to set up a factor and change a node at once. A factor
// added while another was on (confirmed by that one) does not start a wait, and a factor that was
// on before this file existed has none either.
//
// The waits are kept apart from users.db, in second-factor-holds.json in the data directory (mode
// 0600), so that the user store's schema, which older versions of the website must still read, does
// not change. The file is small: a wait is dropped once it is over, and it holds at most
// MAX_HOLDS names. It is written to a temporary file and renamed, so a crash never leaves half of
// it. A file that is there but cannot be read (or is of another version) is moved aside at start,
// to <name>.unreadable-<time>, and said once; the waits start empty, and the operator still has the
// old file to look at. Should it not move, nothing is written over it (the waits are kept in memory
// only). Without a data directory (tests) the waits are kept in memory only.
//
// A wait is never longer than FIRST_FACTOR_HOLD_MS from now: a time further off (a clock set back,
// a file changed by hand) is cut down to that, never dropped, so moving the clock back cannot end
// a wait.
import fs from 'node:fs/promises';
import path from 'node:path';

export const FIRST_FACTOR_HOLD_MS = 24 * 60 * 60_000;
export const HOLDS_FILE = 'second-factor-holds.json';
export const MAX_HOLDS = 10_000;
const MAX_FILE_BYTES = 1024 * 1024;
const KEY_RE = /^[a-z0-9][a-z0-9._-]{0,31}$/;

const keyOf = (name) => (typeof name === 'string' ? name.trim().toLowerCase() : '');

// dataDir: where the file is kept, or null for memory only. now: the clock of the sessions.
export function createFactorHolds({ dataDir = null, now = Date.now, log = console.error, holdMs = FIRST_FACTOR_HOLD_MS } = {}) {
  const file = dataDir === null ? null : path.join(dataDir, HOLDS_FILE);
  // name key -> the time (ms) from which the user may change nodes.
  const holds = new Map();
  let saving = Promise.resolve();
  // false once an unreadable file could not be moved aside: it is never written over.
  let writable = true;

  // Drops the waits that are over, and cuts any longer than holdMs from now down to that.
  const prune = () => {
    const t = now();
    for (const [k, until] of holds) {
      if (until <= t) holds.delete(k);
      else if (until - t > holdMs) holds.set(k, t + holdMs);
    }
  };

  async function writeFile() {
    const tmp = `${file}.${process.pid}.tmp`;
    try {
      await fs.mkdir(path.dirname(file), { recursive: true });
      // A stale temporary file (or a link planted under that name) is removed first, and 'wx'
      // refuses to open anything that is still there.
      await fs.rm(tmp, { force: true });
      const handle = await fs.open(tmp, 'wx', 0o600);
      try {
        await handle.writeFile(JSON.stringify({ version: 1, holds: Object.fromEntries([...holds].map(([k, t]) => [k, new Date(t).toISOString()])) }));
        await handle.sync();
      } finally {
        await handle.close();
      }
      await fs.rename(tmp, file);
    } catch (err) {
      // The wait holds in memory all the same; only a restart before the next write would lose it.
      log(`could not save ${HOLDS_FILE}: ${err.message}`);
      await fs.rm(tmp, { force: true }).catch(() => {});
    }
  }

  const save = () => {
    if (file === null || !writable) return Promise.resolve();
    saving = saving.then(writeFile);
    return saving;
  };

  // Moves a file that cannot be used aside, and says so (why: what is wrong with it).
  async function setAside(why) {
    const aside = `${file}.unreadable-${new Date(now()).toISOString().replace(/[:.]/g, '-')}`;
    try {
      await fs.rename(file, aside);
      log(`warning: ${HOLDS_FILE} ${why}, so it was moved to ${path.basename(aside)} and the waits after turning on two-step sign-in start empty`);
    } catch (err) {
      writable = false;
      log(`warning: ${HOLDS_FILE} ${why}, and it could not be moved aside (${err.code ?? err.message}); it is left as it is and not written over, so waits after turning on two-step sign-in are kept until the server stops only. Move it away and restart`);
    }
  }

  // Reads the file, once at start, before anything is written. Waits that are over, names that are
  // not user names and times that are not times are left out.
  async function load() {
    if (file === null) return;
    let text;
    try {
      const st = await fs.stat(file);
      if (!st.isFile() || st.size > MAX_FILE_BYTES) throw new Error('it is not a small file');
      text = await fs.readFile(file, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return;
      return setAside(`cannot be read (${err.code ?? err.message})`);
    }
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      return setAside('is not valid JSON');
    }
    if (data === null || typeof data !== 'object' || data.version !== 1 || data.holds === null || typeof data.holds !== 'object' || Array.isArray(data.holds)) {
      return setAside('is not of the form this version writes');
    }
    for (const [k, iso] of Object.entries(data.holds).slice(0, MAX_HOLDS)) {
      const t = typeof iso === 'string' ? Date.parse(iso) : NaN;
      if (KEY_RE.test(k) && Number.isFinite(t)) holds.set(k, t);
    }
    prune();
  }

  // Starts the wait for a user who just turned on their first second factor. Gives the time (ms)
  // from which they may change nodes; the wait counts in memory at once, and the write follows.
  async function start(name) {
    const k = keyOf(name);
    const until = now() + holdMs;
    prune();
    holds.delete(k);
    while (holds.size >= MAX_HOLDS) holds.delete(holds.keys().next().value);
    holds.set(k, until);
    await save();
    return until;
  }

  // The time (ms) from which this user may change nodes, or null when they may now.
  function until(name) {
    const t = holds.get(keyOf(name));
    if (t === undefined) return null;
    const at = now();
    if (t <= at) {
      holds.delete(keyOf(name));
      return null;
    }
    if (t - at > holdMs) {
      holds.set(keyOf(name), at + holdMs);
      return at + holdMs;
    }
    return t;
  }

  return { file, load, start, until, flush: () => saving };
}
