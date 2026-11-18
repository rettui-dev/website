// Entry point: reads the environment, starts the monitor and the web server.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_TARGETS, Monitor, parseTargets } from './lib/monitor.js';
import { createApp } from './lib/app.js';

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
const targets = parseTargets(process.env.STATUS_TARGETS || DEFAULT_TARGETS.join(','));

const monitor = new Monitor({ targets, dataDir });
await monitor.load();
monitor.start();

const server = createApp({ monitor, publicDir: path.join(here, 'public') });
server.listen(port, host, () => console.log(`listening on http://${host}:${port}, data in ${dataDir}`));

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    monitor.stop();
    server.close(() => process.exit(0));
    server.closeAllConnections();
  });
}
