import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig, loadNodes } from '../lib/config.js';
import { SECTIONS, stripGroup, stripSeries, stripStats } from '../lib/access.js';

const HASH = '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc';
const yaml = (top = '', node = '') => `${top}
nodes:
  - address: a.test:1
${node}
  - address: b.test:1
`;
const USERS = `users:\n  - name: alice\n    password_hash: '${HASH}'`;
const bad = (text, pattern) => assert.throws(() => loadConfig(text), (e) => pattern.test(e.message), text);

test('users: names and hashes are read; without a rule every section is locked', () => {
  const c = loadConfig(yaml(USERS));
  assert.equal(c.users.length, 1);
  assert.equal(c.users[0].name, 'alice');
  assert.equal(c.users[0].phc.memory, 19456);
  assert.deepEqual(c.defaults.requireLogin, SECTIONS);
  assert.deepEqual(c.nodes.get('a.test:1').requireLogin, SECTIONS);
  assert.deepEqual(c.login, { idleTimeoutMinutes: 60, maxAgeHours: 12, maxSessions: 1000, trustedProxies: [] });
});

test('without users nothing is locked and there is no login', () => {
  const c = loadConfig(yaml());
  assert.deepEqual(c.users, []);
  assert.deepEqual(c.defaults.requireLogin, []);
  assert.deepEqual(c.nodes.get('a.test:1').requireLogin, []);
  // An empty rule names nothing, so it is allowed.
  assert.deepEqual(loadConfig(yaml('require_login: []')).defaults.requireLogin, []);
});

test('a rule or login settings without users stop the start', () => {
  bad(yaml('require_login: [disk]'), /require_login needs "users"/);
  bad(yaml('', '    require_login: [details]'), /nodes\[1\]\.require_login needs "users"/);
  bad(yaml('login:\n  max_sessions: 5'), /"login" needs "users"/);
});

test('require_login: global rule, node override, strict sections', () => {
  const c = loadConfig(yaml(`${USERS}\nrequire_login: [details, disk]`, '    require_login: []'));
  assert.deepEqual(c.defaults.requireLogin, ['details', 'disk']);
  assert.deepEqual(c.nodes.get('a.test:1').requireLogin, []);
  assert.deepEqual(c.nodes.get('b.test:1').requireLogin, ['details', 'disk']);
  bad(yaml(`${USERS}\nrequire_login: [everything]`), /require_login\[1\] must be one of details, storage, peers, disk, versions/);
  bad(yaml(`${USERS}\nrequire_login: [disk, disk]`), /lists disk twice/);
  bad(yaml(`${USERS}\nrequire_login: disk`), /must be a list of sections/);
  bad(yaml(USERS, '    require_login: [1]'), /nodes\[1\]\.require_login\[1\]/);
});

test('users are validated and their hashes never repeated in an error', () => {
  const user = (name, hash = HASH) => `users:\n  - name: ${JSON.stringify(name)}\n    password_hash: '${hash}'`;
  bad(yaml('users: []'), /list of 1 to 64 users/);
  bad(yaml('users: alice'), /list of 1 to 64 users/);
  bad(yaml('users: [alice]'), /users\[1\] must be a map/);
  bad(yaml(user('')), /users\[1\]\.name/);
  bad(yaml(user('a b')), /users\[1\]\.name/);
  bad(yaml(user('-alice')), /users\[1\]\.name/);
  bad(yaml(user('a'.repeat(33))), /users\[1\]\.name/);
  bad(yaml(user('al‮ice')), /users\[1\]\.name/);
  bad(yaml(`users:\n  - name: alice\n    password_hash: '${HASH}'\n  - name: ALICE\n    password_hash: '${HASH}'`), /users\[2\]\.name "ALICE" is listed twice/);
  bad(yaml('users:\n  - name: alice'), /needs a password_hash/);
  bad(yaml(`users:\n  - name: alice\n    password: hunter2\n    password_hash: '${HASH}'`), /unknown key "password"/);
  bad(yaml(user('alice', HASH.replace('m=19456', 'm=4096'))), /users\[1\]\.password_hash is too cheap/);
  bad(yaml(user('alice', HASH.replace('argon2id', 'argon2i'))), /must be argon2id/);
  bad(yaml(user('alice', 'plain text')), /users\[1\]\.password_hash is not an Argon2id hash/);
  bad(yaml(`users:\n  - name: alice\n    password_hash: 12`), /password_hash is not an Argon2id hash/);
  const many = Array.from({ length: 65 }, (_, i) => `  - name: u${i}\n    password_hash: '${HASH}'`).join('\n');
  bad(yaml(`users:\n${many}`), /1 to 64 users/);
  try {
    loadConfig(yaml(user('alice', HASH.replace('m=19456', 'm=4096'))));
  } catch (err) {
    assert.equal(err.message.includes('c29tZXNhbHRzb21lc2FsdA'), false);
    assert.equal(err.message.includes('CTFhFdXP'), false);
  }
});

test('login settings: defaults, ranges and trusted proxies', () => {
  const c = loadConfig(yaml(`${USERS}\nlogin:\n  idle_timeout_minutes: 15\n  max_age_hours: 2\n  max_sessions: 50\n  trusted_proxies: [127.0.0.1, "::1"]`));
  assert.deepEqual(c.login, { idleTimeoutMinutes: 15, maxAgeHours: 2, maxSessions: 50, trustedProxies: ['127.0.0.1', '::1'] });
  bad(yaml(`${USERS}\nlogin: yes`), /"login" must be a map/);
  bad(yaml(`${USERS}\nlogin:\n  secure: false`), /login has an unknown key "secure"/);
  bad(yaml(`${USERS}\nlogin:\n  idle_timeout_minutes: 0`), /idle_timeout_minutes must be a whole number/);
  bad(yaml(`${USERS}\nlogin:\n  max_age_hours: 1.5`), /max_age_hours must be a whole number/);
  bad(yaml(`${USERS}\nlogin:\n  max_sessions: "10"`), /max_sessions must be a whole number/);
  bad(yaml(`${USERS}\nlogin:\n  idle_timeout_minutes: 120\n  max_age_hours: 1`), /cannot be longer/);
  bad(yaml(`${USERS}\nlogin:\n  trusted_proxies: [proxy.local]`), /trusted_proxies\[1\] is not an IP address/);
  bad(yaml(`${USERS}\nlogin:\n  trusted_proxies: 127.0.0.1`), /must be a list/);
});

test('the environment variables have no users and lock nothing', async () => {
  const n = await loadNodes({});
  assert.deepEqual(n.users, []);
  assert.deepEqual(n.defaults.requireLogin, []);
});

const data = () => ({
  rettuiVersion: '2.0.0', uptimeSeconds: 5,
  interfaces: { total: 1, online: 1, clients: 3, rxBytes: 1, txBytes: 1 },
  peersHeard: { total: 7, lxmf: 1, nomad: 1, propagation: 1 }, announcesLastMinute: 2,
  disk: { dataBytes: 9, level: 'high', usedPercent: 80 },
  propagation: { enabled: true, storedMessages: 11, storedBytes: 12, peersAlive: 13, peersTotal: 14, autopeer: true, unhandledMessages: 15 },
});

test('stripStats leaves out each hidden section and nothing else', () => {
  const stats = { ok: true, stale: false, data: data(), peerSummary: { listed: 3 } };
  assert.equal(stripStats(stats, new Set()), stats);
  assert.equal(stripStats(null, new Set(['disk'])), null);
  const all = stripStats(stats, new Set(SECTIONS));
  assert.deepEqual(Object.keys(all.data).sort(), ['announcesLastMinute', 'interfaces', 'peersHeard', 'uptimeSeconds']);
  assert.equal('peerSummary' in all, false);
  // The original is untouched.
  assert.equal(stats.data.disk.level, 'high');
  const storage = stripStats(stats, new Set(['storage'])).data.propagation;
  assert.deepEqual(storage, { enabled: true, peersAlive: 13, peersTotal: 14, autopeer: true });
  const peers = stripStats(stats, new Set(['peers']));
  assert.deepEqual(peers.data.propagation, { enabled: true, storedMessages: 11, storedBytes: 12, unhandledMessages: 15 });
  assert.equal('peerSummary' in peers, false);
  assert.equal(stripStats(stats, new Set(['versions'])).data.rettuiVersion, undefined);
  assert.equal(stripStats({ ok: false, error: 'x' }, new Set(SECTIONS)).ok, false);
});

test('stripGroup and stripSeries take the sums and the graphs out', () => {
  const group = { nodes: 2, data: { peersHeard: { sum: {} }, disk: { worst: { level: 'full' } }, propagation: { nodes: 2, storedMessages: 1, peersAlive: 2 } } };
  assert.equal(stripGroup(group, new Set()), group);
  assert.deepEqual(stripGroup(group, new Set(['disk', 'storage', 'peers'])).data, { peersHeard: { sum: {} }, disk: null, propagation: null });
  assert.deepEqual(stripGroup(group, new Set(['storage'])).data.propagation, { nodes: 2, peersAlive: 2 });
  assert.equal(stripGroup({ nodes: 1, data: null }, new Set(['disk'])).data, null);
  const series = { bytesIn: [], disk: { fsFreeBytes: [] }, propagation: { storedMessages: [], storedBytes: [], peersAlive: [], peersTotal: [], sentPerMinute: [], receivedPerMinute: [], members: 2 } };
  assert.deepEqual(stripSeries(series, new Set(['disk', 'storage'])), { bytesIn: [], disk: null, propagation: { peersAlive: [], peersTotal: [], members: 2 } });
  assert.equal(stripSeries(series, new Set(['storage', 'peers'])).propagation, null);
  assert.deepEqual(Object.keys(stripSeries(series, new Set(['peers'])).propagation).sort(), ['members', 'receivedPerMinute', 'sentPerMinute', 'storedBytes', 'storedMessages']);
});
