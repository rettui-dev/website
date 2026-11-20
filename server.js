// Entry point: reads the environment, starts the monitor and the web server.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from './lib/monitor.js';
import { loadNodes } from './lib/config.js';
import { createApp } from './lib/app.js';
import { createAlerter } from './lib/alerts.js';
import { createLogin } from './lib/login.js';
import { StoreError, UserStore, readStore, storeHasUsers } from './lib/users.js';
import { createAudit, createFailureLog } from './lib/audit.js';
import { ReleaseCache, loadReleaseSettings } from './lib/releases.js';
import { argon2Available } from './lib/password.js';
import { SAMPLE_INTERVAL_MS } from './lib/history.js';

const here = path.dirname(fileURLToPath(import.meta.url));

function parsePort(text) {
  if (!/^\d{1,5}$/.test(text) || Number(text) < 1 || Number(text) > 65535) {
    throw new Error(`PORT "${text}" is not a port number`);
  }
  return Number(text);
}

const port = parsePort(process.env.PORT ?? '8080');
const host = process.env.HOST || '0.0.0.0';
const dataDir = path.resolve(process.env.DATA_DIR || path.join(here, 'data'));

// The users made on the website and everyone's second factor. It is read before the config file,
// whose login settings are allowed once users.json has users. A store that cannot be read stops
// the server, and is left as it is.
let stored;
try {
  stored = await readStore({ dataDir });
} catch (err) {
  if (!(err instanceof StoreError)) throw err;
  console.error(`cannot start: ${err.message}`);
  process.exit(1);
}

const { targets, statsUrls, nodes, tokens, warnings, defaults, users, login, alerts: alertSettings, siteMode, site } = await loadNodes(
  { ...process.env, CONFIG_FILE: process.env.CONFIG_FILE && path.resolve(process.env.CONFIG_FILE) },
  { storeUsers: storeHasUsers(stored.data) },
);
for (const w of warnings ?? []) console.warn(w);

// STATS_SAMPLE_INTERVAL_MS is for testing only: it makes the stats history fill
// faster than the 5 minute default.
const sampleIntervalMs = process.env.STATS_SAMPLE_INTERVAL_MS ? Number(process.env.STATS_SAMPLE_INTERVAL_MS) : SAMPLE_INTERVAL_MS;
if (!Number.isInteger(sampleIntervalMs) || sampleIntervalMs < 1000) throw new Error('STATS_SAMPLE_INTERVAL_MS must be a whole number of at least 1000');

const store = new UserStore({ file: stored.file, configUsers: users, data: stored.data });

// Checked now rather than at the first login, so a wrong Node.js is noticed at once.
if ((users.length || store.hasLocalUsers()) && !argon2Available()) throw new Error(`users need Node.js 24.7 or later for Argon2id (this is ${process.version})`);

// Messages for the operator when a node goes down or comes back; only the monitor sends them.
const alerts = createAlerter(alertSettings, nodes);
if (alerts) console.log(`alerts: ${alertSettings.channels.map((c) => c.type).join(', ')} for ${alertSettings.events.join(', ')}`);

const monitor = new Monitor({ alerts, targets, dataDir, statsUrls, nodes, tokens, publicDetails: defaults.publicDetails, publicDiskFigures: defaults.publicDiskFigures, publicLogs: defaults.publicLogs, requireLogin: defaults.requireLogin, sampleIntervalMs, logsEnabled: true });
await monitor.load();
monitor.start();

// The latest releases for the Downloads page: read from releases.json now, refreshed in the
// background. A status-only site has no Downloads page, so nothing is read or fetched.
let releases = null;
if (siteMode === 'full') {
  const releaseSettings = await loadReleaseSettings(process.env);
  releases = new ReleaseCache({ ...releaseSettings, dataDir });
  await releases.load();
  releases.start();
}

// Security events go to audit.log; wrong passwords and codes, summed up, to failures.log.
const failures = createFailureLog({ dataDir });
failures.start();
const audit = createAudit({ dataDir });
const server = createApp({ monitor, publicDir: path.join(here, 'public'), login: createLogin({ users, store, settings: login, audit, failures }), releases, mode: siteMode, site });
server.listen(port, host, () => console.log(`listening on http://${host}:${port}, ${siteMode === 'status' ? 'status-only site, ' : ''}data in ${dataDir}`));

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    monitor.stop();
    alerts?.stop();
    releases?.stop();
    failures.stop();
    // The last uptime and history, the failures summed up so far, the audit lines and the user
    // store writes still under way are all written before the process ends.
    Promise.all([monitor.flush(), failures.flush(), audit.flush(), store.flush()]).catch((err) => console.error(`final save failed: ${err.message}`)).finally(() => {
      server.close(() => process.exit(0));
      server.closeAllConnections();
    });
  });
}
