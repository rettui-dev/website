// The audit log: audit.log in the data directory, one JSON object per line, appended to, mode 0600.
// It records security events only: changes to how someone signs in (password, second factor,
// recovery codes, sessions ended, devices added and removed) and changes to users. It never holds a
// password, secret, code or device id.
//
// Wrong passwords and codes go to failures.log instead (createFailureLog), summed up: one line per
// name and kind of failure per period. So no amount of failures can push a security event out of
// audit.log.
//
// Both are bounded: a line that would take a log past maxBytes first moves it to <log>.1 (and
// <log>.1 to <log>.2, and so on); only `keep` files are kept in all, the oldest is dropped. So no
// request, however often it is sent, can fill the disk with them.
import fs from 'node:fs/promises';
import path from 'node:path';

export const AUDIT_FILE = 'audit.log';
export const FAILURES_FILE = 'failures.log';
export const AUDIT_MAX_BYTES = 5 * 1024 * 1024;
export const AUDIT_KEEP = 3;
// Failures of one key are summed up over this long, then written as one line.
export const FAILURE_PERIOD_MS = 15 * 60_000;
// At most this many keys are summed up at once; past that the oldest summary is written early.
export const MAX_FAILURE_KEYS = 10_000;
// Distinct addresses counted per summary; past this the count says "at least".
const MAX_ADDRESSES_COUNTED = 100;

// <log> becomes <log>.1, <log>.1 becomes <log>.2, ...; the last of the kept files is dropped. A
// rename keeps the mode (0600).
async function rotate(file, keep) {
  await fs.rm(`${file}.${keep - 1}`, { force: true });
  for (let i = keep - 2; i >= 1; i--) {
    await fs.rename(`${file}.${i}`, `${file}.${i + 1}`).catch((err) => {
      if (err.code !== 'ENOENT') throw err;
    });
  }
  if (keep > 1) await fs.rename(file, `${file}.1`);
  else await fs.rm(file, { force: true });
}

async function append(file, line, maxBytes, keep) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const size = await fs.stat(file).then((st) => st.size, (err) => {
    if (err.code === 'ENOENT') return 0;
    throw err;
  });
  if (size > 0 && size + Buffer.byteLength(line) > maxBytes) await rotate(file, keep);
  const handle = await fs.open(file, 'a', 0o600);
  try {
    // The mode only applies to a new file; an old one made looser by hand is put back.
    if (process.platform !== 'win32') {
      const st = await handle.stat();
      if ((st.mode & 0o077) !== 0) await handle.chmod(0o600);
    }
    await handle.appendFile(line);
  } finally {
    await handle.close();
  }
}

// Appends lines to one file, one write after another. A failed write is logged and does not fail
// whatever it records.
// write.idle() resolves once every line asked for so far, and any asked for meanwhile, is written.
function writer(file, { now, log, maxBytes, keep, what }) {
  let chain = Promise.resolve();
  const write = (event, fields = {}) => {
    const line = `${JSON.stringify({ time: new Date(now()).toISOString(), event, ...fields })}\n`;
    chain = chain.then(() => append(file, line, maxBytes, keep)).catch((err) => log(`could not write the ${what}: ${err.message}`));
    return chain;
  };
  write.idle = async () => {
    let p;
    do {
      p = chain;
      await p;
    } while (p !== chain);
  };
  return write;
}

// write(event, fields) appends one line and returns when it is written; flush() resolves once
// every line asked for is written (the server waits for it before it stops).
export function createAudit({ dataDir, now = Date.now, log = console.error, maxBytes = AUDIT_MAX_BYTES, keep = AUDIT_KEEP }) {
  const file = path.join(dataDir, AUDIT_FILE);
  const write = writer(file, { now, log, maxBytes, keep, what: 'audit log' });
  return { file, write, flush: write.idle };
}

// The failures log. note(event, key, {user, address}) counts one failure; the failures of a key are
// written as one line when its period is over: {event, user, failures, addresses, from, to,
// lastAddress}. Due summaries are written by the next note, by flushDue() (start() runs it every
// period) and all of them by flush(), at the latest when the server stops.
export function createFailureLog({ dataDir, now = Date.now, log = console.error, maxBytes = AUDIT_MAX_BYTES, keep = AUDIT_KEEP, periodMs = FAILURE_PERIOD_MS, maxKeys = MAX_FAILURE_KEYS }) {
  const file = path.join(dataDir, FAILURES_FILE);
  const write = writer(file, { now, log, maxBytes, keep, what: 'failures log' });
  // Open summaries by event and key, oldest first.
  const open = new Map();
  let last = Promise.resolve();
  let timer = null;

  const emit = (s) => {
    const addresses = s.addresses.size >= MAX_ADDRESSES_COUNTED ? `${MAX_ADDRESSES_COUNTED}+` : s.addresses.size;
    last = write(s.event, { user: s.user, failures: s.count, addresses, from: new Date(s.from).toISOString(), to: new Date(s.to).toISOString(), lastAddress: s.lastAddress });
    return last;
  };

  function flushDue() {
    const t = now();
    for (const [k, s] of open) {
      if (t - s.from >= periodMs || t < s.from) {
        open.delete(k);
        emit(s);
      }
    }
    return last;
  }

  return {
    file,
    note(event, key, { user = null, address = null } = {}) {
      flushDue();
      const k = `${event}|${key}`;
      const t = now();
      let s = open.get(k);
      if (!s) {
        while (open.size >= maxKeys) {
          const [oldest, summary] = open.entries().next().value;
          open.delete(oldest);
          emit(summary);
        }
        s = { event, user, count: 0, addresses: new Set(), from: t, to: t, lastAddress: null };
        open.set(k, s);
      }
      s.count++;
      s.to = t;
      if (address !== null) {
        if (s.addresses.size < MAX_ADDRESSES_COUNTED) s.addresses.add(address);
        s.lastAddress = address;
      }
      return last;
    },
    flushDue,
    // Writes every open summary now; resolves once they are written.
    flush() {
      for (const [k, s] of open) {
        open.delete(k);
        emit(s);
      }
      return last;
    },
    // Writes due summaries every period, without keeping the process alive.
    start() {
      if (timer) return;
      timer = setInterval(flushDue, periodMs);
      timer.unref();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
    },
    get size() {
      return open.size;
    },
  };
}

// For a site without a data directory to write to (tests, mostly).
export const NO_AUDIT = Object.freeze({ file: null, write: async () => {}, flush: async () => {} });
export const NO_FAILURES = Object.freeze({ file: null, note: async () => {}, flushDue: async () => {}, flush: async () => {}, start: () => {}, stop: () => {}, size: 0 });
