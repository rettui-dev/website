// Entry point: reads the environment, starts the monitor and the web server.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from './lib/monitor.js';
import { loadNodes } from './lib/config.js';
import { createApp } from './lib/app.js';
import { createLogin } from './lib/login.js';
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

const { targets, statsUrls, nodes, tokens, warnings, defaults, users, login } = await loadNodes({ ...process.env, CONFIG_FILE: process.env.CONFIG_FILE && path.resolve(process.env.CONFIG_FILE) });
for (const w of warnings ?? []) console.warn(w);

// STATS_SAMPLE_INTERVAL_MS is for testing only: it makes the stats history fill
// faster than the 5 minute default.
const sampleIntervalMs = process.env.STATS_SAMPLE_INTERVAL_MS ? Number(process.env.STATS_SAMPLE_INTERVAL_MS) : SAMPLE_INTERVAL_MS;
if (!Number.isInteger(sampleIntervalMs) || sampleIntervalMs < 1000) throw new Error('STATS_SAMPLE_INTERVAL_MS must be a whole number of at least 1000');

// Checked now rather than at the first login, so a wrong Node.js is noticed at once.
if (users.length && !argon2Available()) throw new Error(`users in CONFIG_FILE need Node.js 24.7 or later for Argon2id (this is ${process.version})`);

const monitor = new Monitor({ targets, dataDir, statsUrls, nodes, tokens, publicDetails: defaults.publicDetails, publicDiskFigures: defaults.publicDiskFigures, requireLogin: defaults.requireLogin, sampleIntervalMs });
await monitor.load();
monitor.start();

const server = createApp({ monitor, publicDir: path.join(here, 'public'), login: createLogin({ users, settings: login }) });
server.listen(port, host, () => console.log(`listening on http://${host}:${port}, data in ${dataDir}`));

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    monitor.stop();
    server.close(() => process.exit(0));
    server.closeAllConnections();
  });
}
