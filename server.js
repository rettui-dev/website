// Entry point: reads the environment, starts the monitor and the web server.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from './lib/monitor.js';
import { loadNodes } from './lib/config.js';
import { createApp } from './lib/app.js';
import { createManageClient, forgetManageSecrets } from './lib/manage.js';
import { LinkWatcher, linkEntries } from './lib/links.js';
import { createAlerter } from './lib/alerts.js';
import { createLogin } from './lib/login.js';
import { NO_PASSKEYS, createPasskeys, passkeyOriginProblem } from './lib/passkeys.js';
import { StoreError, UserStore, storeHasUsers } from './lib/users.js';
import { DB_FILE, NO_KEY, StoreBusyError, openUserDb } from './lib/userdb.js';
import { KeyError, loadKeys } from './lib/keys.js';
import { createAudit, createFailureLog } from './lib/audit.js';
import { createFactorHolds } from './lib/factor-hold.js';
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

// Stops the start with a message for the operator, and no stack trace.
function refuse(message) {
  console.error(`cannot start: ${message}`);
  process.exit(1);
}

// The keys that protect the user store (keys.js), from USERS_KEY_FILE or USERS_KEY, or null.
let keys;
try {
  keys = await loadKeys(process.env, { dataDir });
} catch (err) {
  if (!(err instanceof KeyError)) throw err;
  refuse(err.message);
}

// The users made on the website and everyone's second factor, in users.db (made, and users.json
// imported, at the first start). It is read before the config file, whose login settings are
// allowed once the store has users. A store that cannot be read stops the server, and is left as
// it is.
let opened;
try {
  opened = await openUserDb({ dataDir, keys, timeoutMs: 1000 });
} catch (err) {
  if (!(err instanceof StoreError || err instanceof StoreBusyError || err instanceof KeyError)) throw err;
  refuse(err.message);
}

// The config file and the variables. What is wrong with them is said plainly, without a stack trace.
let config;
try {
  config = await loadNodes({ ...process.env, CONFIG_FILE: process.env.CONFIG_FILE && path.resolve(process.env.CONFIG_FILE) }, { storeUsers: storeHasUsers(opened.data) });
} catch (err) {
  opened.db.close();
  refuse(err.message);
}
const { targets, statsUrls, nodes, tokens, warnings, defaults, users, login, alerts: alertSettings, siteMode, site } = config;
for (const w of warnings ?? []) console.warn(w);

// A users.json with users that was never imported, next to a store without users and a config
// file without users: the site would run without anyone able to sign in, every section public,
// while the operator meant it to have users.
if (opened.jsonNotImported && !storeHasUsers(opened.data) && users.length === 0) {
  opened.db.close();
  refuse(`users.json in the data directory has users, but was never imported: ${DB_FILE} was made without it and has no users, so the site would run without sign-in. To import it, stop the server, move ${DB_FILE}* away and start; to run without it, move users.json out of the data directory`);
}

// STATS_SAMPLE_INTERVAL_MS is for testing only: it makes the stats history fill
// faster than the 5 minute default.
const sampleIntervalMs = process.env.STATS_SAMPLE_INTERVAL_MS ? Number(process.env.STATS_SAMPLE_INTERVAL_MS) : SAMPLE_INTERVAL_MS;
if (!Number.isInteger(sampleIntervalMs) || sampleIntervalMs < 1000) throw new Error('STATS_SAMPLE_INTERVAL_MS must be a whole number of at least 1000');

// Signing in needs a key: second factors are kept encrypted with it, and new passwords peppered.
// The store refuses users without one already; users only in the config file are refused here.
if (keys === null && (users.length > 0 || storeHasUsers(opened.data))) {
  opened.db.close();
  refuse(NO_KEY);
}

// opened.keys: the versions users.db has recorded, which here are all of those given.
// The second factors kept for users who are no longer in the config file are not used: a new user with
// that name must not get them. They are named in a warning and removed, and each is an audit line. Not
// when the config file has no users at all: a config file that is not set or has lost its users is more
// likely a mistake than every one of them having left, so the records are left alone.
const dropOrphans = users.length > 0;
const store = new UserStore({ db: opened.db, data: opened.data, configUsers: users, keys: opened.keys, dropOrphans });
const orphaned = [...store.orphans];
store.forgetOrphans();
// Written at once, before anything later in start-up can fail: the records are already gone.
const audit = createAudit({ dataDir });
if (opened.imported !== null) await audit.write('user-store-imported', { users: opened.imported.users, configUsers: opened.imported.configUsers, ...(opened.reimported ? { again: true } : {}) });
for (const version of opened.addedKeys) await audit.write('key-added', { version });
for (const user of orphaned) await audit.write('second-factor-orphaned', { user });
const leftover = dropOrphans ? 0 : (opened.data?.configUsers.length ?? 0);
if (leftover > 0) {
  console.warn(`warning: the user store keeps the second factors (passkeys, an app code) of ${leftover} ${leftover === 1 ? 'user' : 'users'} from the config file, but ${process.env.CONFIG_FILE ? 'the config file has no users' : 'CONFIG_FILE is not set'}. They were left alone, in case the config file is missing or wrong; they are removed only when the config file has users and a user is not in it.`);
}
// Changes made by scripts/users.js while the server runs are picked up within a second.
store.watch();

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
// Passkeys work at the site's own address (site.url or SITE_URL) only: without one they are off,
// and users who have one sign in with their app code or a recovery code.
const passkeys = site.url ? createPasskeys({ siteUrl: site.url, rpName: site.name ?? 'rettui status', store }) : NO_PASSKEYS;
if ((users.length || store.hasLocalUsers()) && !passkeys.available) console.log(`passkeys: off, as ${passkeyOriginProblem(site.url)}`);
else if (passkeys.available && login.passkeySignIn === false) console.log('passkey sign-in: off (login.passkey_sign_in is false)');
// The nodes that can be managed from the website (manage_url and manage_secret_file in the config
// file). Their secrets are kept by the client only, in memory: once it has copied them, they are
// cleared from the config.
const manageNodes = config.manage ?? new Map();
const manage = manageNodes.size > 0 ? { client: createManageClient({ nodes: manageNodes }), nodes: [...manageNodes.keys()] } : null;
forgetManageSecrets(manageNodes);
// Links between nodes found in the managed nodes' Reticulum configs: only with detect_links in the
// config file, and only when there are users (without them nothing is managed from here). They are
// read slowly, on a schedule of their own and never for a page view; LINKS_DEBUG=1 also logs what was
// dropped. Declared links (links in the config file) need none of this.
const hasUsers = users.length > 0 || store.hasLocalUsers();
if (config.detectLinks && manage && hasUsers) {
  const watcher = new LinkWatcher({ client: manage.client, entries: linkEntries({ targets, nodes, manage: manageNodes, statsUrls }), log: (m) => console.warn(m), debug: process.env.LINKS_DEBUG === '1' ? (m) => console.debug(m) : undefined });
  monitor.attachLinks(watcher);
  watcher.start();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => watcher.stop());
} else if (config.detectLinks) console.warn('warning: detect_links is on, but no node has a manage_url or the site has no users, so no links are read from the nodes');
if (manage && !(users.length || store.hasLocalUsers())) console.warn(`warning: ${manageNodes.size === 1 ? 'a node has' : `${manageNodes.size} nodes have`} a manage_url, but the site has no users, so nobody can manage ${manageNodes.size === 1 ? 'it' : 'them'} until a user with the manage or admin role is added`);
// The waits after a first second factor, before node changes (factor-hold.js).
const holds = createFactorHolds({ dataDir });
await holds.load();
const server = createApp({ monitor, publicDir: path.join(here, 'public'), login: createLogin({ users, store, settings: login, audit, failures, passkeys }), releases, mode: siteMode, site, manage, holds });
server.listen(port, host, () => console.log(`listening on http://${host}:${port}, ${siteMode === 'status' ? 'status-only site, ' : ''}data in ${dataDir}`));

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    monitor.stop();
    alerts?.stop();
    releases?.stop();
    failures.stop();
    // The last uptime and history, the failures summed up so far and the audit lines are all
    // written before the process ends. User store writes are done when they return.
    Promise.all([monitor.flush(), failures.flush(), audit.flush(), store.flush(), holds.flush()])
      .catch((err) => console.error(`final save failed: ${err.message}`))
      .finally(() => {
        // The store is closed once no request can write to it any more.
        server.close(() => {
          store.close();
          process.exit(0);
        });
        server.closeAllConnections();
      });
  });
}
