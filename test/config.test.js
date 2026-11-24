import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, loadConfigFile, loadNodes, MAX_CONFIG_BYTES, MAX_NODES } from '../lib/config.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

const ok = `
nodes:
  - address: A.Test:4242
    name: " Front door "
    stats_url: https://a.test/stats.json
    proxy_for: [b.test:4242, c.test:4242]
    count_own: true
  - address: b.test:4242
    stats_url: http://127.0.0.1:9/s.json
  - address: c.test:4242
    name: C
`;

test('loadConfig reads nodes, names, stats URLs and proxies', () => {
  const c = loadConfig(ok);
  assert.deepEqual(c.targets, [{ host: 'a.test', port: 4242 }, { host: 'b.test', port: 4242 }, { host: 'c.test', port: 4242 }]);
  assert.deepEqual([...c.statsUrls], [['a.test:4242', 'https://a.test/stats.json'], ['b.test:4242', 'http://127.0.0.1:9/s.json']]);
  assert.deepEqual(c.nodes.get('a.test:4242'), { name: 'Front door', proxyFor: ['b.test:4242', 'c.test:4242'], proxiedBy: null, countOwn: true, publicDetails: true, publicDiskFigures: false, publicLogs: false, requireLogin: [] });
  assert.deepEqual(c.nodes.get('b.test:4242'), { name: null, proxyFor: [], proxiedBy: 'a.test:4242', countOwn: false, publicDetails: true, publicDiskFigures: false, publicLogs: false, requireLogin: [] });
  assert.equal(c.nodes.get('c.test:4242').name, 'C');
});

test('the example config in the repository is valid', async () => {
  const c = await loadConfigFile(path.join(root, 'config.example.yaml'));
  assert.equal(c.targets.length, 4);
  assert.equal(c.statsUrls.size, 4);
  assert.equal(c.nodes.get('rns.rettui.dev:4242').proxyFor.length, 3);
});

const bad = (text, pattern) => assert.throws(() => loadConfig(text), (e) => e instanceof Error && pattern.test(e.message), text);
const one = (extra = '') => `nodes:\n  - address: a.test:1\n${extra}`;

test('structure errors', () => {
  bad('', /top level/);
  bad('just text', /top level/);
  bad('[1, 2]', /top level/);
  bad('nodes: []', /at least one/);
  bad('nodes: {a: 1}', /at least one/);
  bad('nodes: [1]', /nodes\[1\] must be a map/);
  bad('nodes: [[a]]', /must be a map/);
  bad('nodes:\n  - address: a.test:1\nextra: 1', /unknown key "extra"/);
  bad(one('    colour: red'), /unknown key "colour"/);
  bad('nodes:\n  - name: x', /needs an address/);
  bad('nodes: [ {address: a.test:1}, ', /invalid YAML|valid YAML/);
});

test('a peppered hash in the config file is refused, without repeating it', () => {
  const plain = '$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc';
  const peppered = plain.replace('p=1$', 'p=1,keyid=AAAAAQ$');
  const users = (hash) => `users:\n  - name: alice\n    password_hash: '${hash}'\n${one()}`;
  assert.equal(loadConfig(users(plain)).users[0].phc.keyid, null);
  bad(users(peppered), /users\[1\]\.password_hash has a keyid: hashes in the config file cannot be peppered/);
  assert.throws(() => loadConfig(users(peppered)), (e) => !e.message.includes('c29tZXNhbHQ') && !e.message.includes('AAAAAQ'));
});

test('wrong types and bad values', () => {
  for (const a of ['5', 'true', 'null', '[a.test:1]', '{a: 1}', '"a.test:1,b.test:2"', 'nohost', '"a.test:0"', '"a.test:99999"', '"a b:80"', '""']) {
    bad(`nodes:\n  - address: ${a}`, /address/);
  }
  bad(one('    name: 5'), /name must be text/);
  bad(one('    name: ""'), /1 to 48/);
  bad(one(`    name: ${'x'.repeat(49)}`), /1 to 48/);
  bad(one('    name: "a\\u0007b"'), /control characters/);
  bad(one('    stats_url: 5'), /stats_url/);
  bad(one('    stats_url: ftp://a.test/x'), /stats_url/);
  bad(one('    stats_url: https://user:pw@a.test/x'), /stats_url/);
  bad(one('    stats_url: http://a.test/x'), /plain http/);
  bad(one('    stats_url: not a url'), /stats_url/);
  bad(one('    count_own: true'), /only makes sense/);
  bad(one('    count_own: "yes"\n    proxy_for: [b.test:1]'), /true or false/);
  bad(one('    proxy_for: a.test:2'), /list/);
  bad(one('    proxy_for: []'), /list/);
  bad(one('    proxy_for: [5]'), /proxy_for\[1\]/);
});

test('errors never repeat a URL', () => {
  const secret = 'https://user:SECRET-TOKEN@a.test/x?key=SECRET-TOKEN';
  for (const text of [one(`    stats_url: ${secret}`), one(`    stats_url: "http://a.test/SECRET-TOKEN"`), `nodes:\n  - address: a.test:1\n    stats_url: ${secret}\n  bad: SECRET-TOKEN`]) {
    assert.throws(() => loadConfig(text), (e) => !/SECRET-TOKEN/.test(e.message));
  }
});

test('duplicates are rejected, including repeated YAML keys', () => {
  bad('nodes:\n  - address: a.test:1\n  - address: A.TEST:1', /lists a.test:1 twice/);
  bad(one('    name: x\n    name: y'), /DUPLICATE_KEY|valid YAML|invalid YAML/);
  bad('nodes: []\nnodes: []', /DUPLICATE_KEY|invalid YAML/);
  bad('nodes:\n  - address: a.test:1\n  - address: b.test:1\n    proxy_for: [a.test:1, a.test:1]', /twice/);
});

test('proxy rules', () => {
  const nodes = (...ns) => 'nodes:\n' + ns.map((n) => `  - ${n.replaceAll('\n', '\n    ')}`).join('\n');
  bad(nodes('address: a.test:1\nproxy_for: [z.test:1]'), /not one of the nodes/);
  bad(nodes('address: a.test:1\nproxy_for: [a.test:1]'), /cannot proxy itself/);
  bad(nodes('address: a.test:1\nproxy_for: [b.test:1]', 'address: b.test:1\nproxy_for: [a.test:1]'), /cycle/);
  bad(nodes('address: a.test:1\nproxy_for: [b.test:1]', 'address: b.test:1\nproxy_for: [c.test:1]', 'address: c.test:1\nproxy_for: [a.test:1]'), /cycle/);
  bad(nodes('address: a.test:1\nproxy_for: [b.test:1]', 'address: b.test:1\nproxy_for: [c.test:1]', 'address: c.test:1'), /nested/);
  bad(nodes('address: a.test:1\nproxy_for: [c.test:1]', 'address: b.test:1\nproxy_for: [c.test:1]', 'address: c.test:1'), /one proxy/);
  const fine = loadConfig(nodes('address: a.test:1\nproxy_for: [b.test:1]', 'address: b.test:1', 'address: c.test:1\nproxy_for: [d.test:1]', 'address: d.test:1'));
  assert.equal(fine.nodes.get('d.test:1').proxiedBy, 'c.test:1');
});

test('at most 64 nodes', () => {
  const list = (n) => 'nodes:\n' + Array.from({ length: n }, (_, i) => `  - address: n${i}.test:1`).join('\n');
  assert.equal(loadConfig(list(MAX_NODES)).targets.length, MAX_NODES);
  bad(list(MAX_NODES + 1), /more than 64/);
});

test('hostile YAML: aliases, merge keys, tags, other documents', () => {
  bad('nodes:\n  - &n\n    address: a.test:1\n  - *n', /alias|invalid YAML|ALIAS/i);
  const bomb = ['a: &a [x, x, x, x, x, x, x, x, x]', ...'bcdefghi'.split('').map((k, i) => `${k}: &${k} [${Array(9).fill('*' + 'abcdefghi'[i]).join(', ')}]`)].join('\n');
  bad(`${bomb}\nnodes: *i`, /alias|invalid YAML|ALIAS|top level|unknown key/i);
  bad('base: &b {address: a.test:1}\nnodes:\n  - <<: *b', /alias|invalid YAML|ALIAS|unknown key/i);
  bad('nodes:\n  - <<: {address: a.test:1}', /unknown key "<<"/);
  bad('nodes:\n  - address: !!js/function "x"', /invalid YAML|TAG/i);
  bad('nodes:\n  - address: !custom a.test:1', /invalid YAML|TAG/i);
  bad('nodes:\n  - address: !!binary YQ==', /invalid YAML|address|TAG/i);
  bad('%TAG ! tag:example.com,2000:\n---\nnodes:\n  - address: !x a.test:1', /invalid YAML|TAG/i);
  bad('nodes:\n  - address: a.test:1\n---\nnodes:\n  - address: b.test:1', /invalid YAML|MULTIPLE/i);
  bad('nodes:\n  - __proto__: {x: 1}\n    address: a.test:1', /unknown key "__proto__"/);
});

test('a huge or deeply nested file is refused without a crash', () => {
  bad(`nodes:\n  - address: a.test:1\n    name: ${'x'.repeat(MAX_CONFIG_BYTES)}`, /larger than 64 KiB/);
  bad('nodes: ' + '['.repeat(20000) + ']'.repeat(20000), /./);
  bad('nodes: ' + '{a: '.repeat(20000), /./);
  bad(Buffer.from([0xff, 0xfe, 0x00]).toString('latin1') + '\0\0', /./);
  assert.throws(() => loadConfig(undefined), /not text/);
});

test('loadConfigFile checks the size before reading, and the path', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  const big = path.join(dir, 'big.yaml');
  await fs.writeFile(big, 'x'.repeat(MAX_CONFIG_BYTES + 1));
  await assert.rejects(loadConfigFile(big), /larger than 64 KiB/);
  await assert.rejects(loadConfigFile(path.join(dir, 'missing.yaml')), /cannot read the file \(ENOENT\)/);
  await assert.rejects(loadConfigFile(dir), /not a file/);
  const good = path.join(dir, 'good.yaml');
  await fs.writeFile(good, ok);
  assert.equal((await loadConfigFile(good)).targets.length, 3);
});

test('loadNodes: the environment variables work as before when there is no config file', async () => {
  const defaults = await loadNodes({});
  assert.equal(defaults.targets.length, 4);
  assert.equal(defaults.statsUrls.size, 0);
  assert.equal(defaults.nodes.size, 0);
  const env = await loadNodes({ STATUS_TARGETS: 'a.test:1,b.test:2', STATS_URLS: 'b.test:2=https://b.test/s.json' });
  assert.deepEqual(env.targets, [{ host: 'a.test', port: 1 }, { host: 'b.test', port: 2 }]);
  assert.equal(env.statsUrls.get('b.test:2'), 'https://b.test/s.json');
  assert.equal(env.nodes.size, 0);
  await assert.rejects(loadNodes({ STATUS_TARGETS: 'nohost' }), /STATUS_TARGETS/);
  await assert.rejects(loadNodes({ STATS_URLS: 'a.test:4242=https://x' }), /STATS_URLS/);
  assert.equal((await loadNodes({ STATUS_TARGETS: '', STATS_URLS: '' })).targets.length, 4);
});

test('loadNodes: LOGIN_TRUSTED_PROXIES sets the trusted proxies without a config file, checked like trusted_proxies', async () => {
  const env = await loadNodes({ LOGIN_TRUSTED_PROXIES: '127.0.0.1, 0:0:0:0:0:0:0:1' }, { storeUsers: true });
  assert.deepEqual(env.login.trustedProxies, ['127.0.0.1', '::1']);
  assert.deepEqual(env.warnings, []);
  assert.deepEqual((await loadNodes({}, { storeUsers: true })).login.trustedProxies, []);
  // Without users in users.json it is not used, and the operator is told.
  const unused = await loadNodes({ LOGIN_TRUSTED_PROXIES: '10.0.0.1' });
  assert.match(unused.warnings.join('\n'), /LOGIN_TRUSTED_PROXIES is set, but users.json has no users/);
  await assert.rejects(loadNodes({ LOGIN_TRUSTED_PROXIES: '' }), /LOGIN_TRUSTED_PROXIES is empty/);
  await assert.rejects(loadNodes({ LOGIN_TRUSTED_PROXIES: '10.0.0.1,proxy.local' }), /LOGIN_TRUSTED_PROXIES: entry 2 is not an IP address/);
  await assert.rejects(loadNodes({ LOGIN_TRUSTED_PROXIES: '10.0.0.1,' }), /entry 2 is not an IP address/);
  await assert.rejects(loadNodes({ LOGIN_TRUSTED_PROXIES: Array.from({ length: 17 }, (_, i) => `10.0.0.${i}`).join(',') }), /at most 16/);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  const file = path.join(dir, 'c.yaml');
  await fs.writeFile(file, ok);
  await assert.rejects(loadNodes({ CONFIG_FILE: file, LOGIN_TRUSTED_PROXIES: '10.0.0.1' }), /login\.trusted_proxies/);
});

test('login.passkey_sign_in: on by default, true or false in the file, and nothing else', () => {
  const nodes = 'nodes:\n  - address: a.test:1\n';
  assert.equal(loadConfig(nodes).login.passkeySignIn, true);
  assert.equal(loadConfig(`${nodes}login:\n  max_sessions: 10\n`, { storeUsers: true }).login.passkeySignIn, true);
  assert.equal(loadConfig(`${nodes}login:\n  passkey_sign_in: true\n`, { storeUsers: true }).login.passkeySignIn, true);
  const off = loadConfig(`${nodes}login:\n  passkey_sign_in: false\n  max_sessions: 10\n`, { storeUsers: true }).login;
  assert.equal(off.passkeySignIn, false);
  assert.equal(off.maxSessions, 10);
  // Only a real true or false: YAML would read "no", 0 and "false" as other things.
  for (const bad of ['"false"', '"true"', 'no', '0', '1', 'null', '[]', '{}', '""']) {
    assert.throws(() => loadConfig(`${nodes}login:\n  passkey_sign_in: ${bad}\n`, { storeUsers: true }), /login\.passkey_sign_in must be true or false/, bad);
  }
  // Another spelling of the key is an unknown key, not a switch.
  assert.throws(() => loadConfig(`${nodes}login:\n  passkeySignIn: false\n`, { storeUsers: true }), /login has an unknown key "passkeySignIn"/);
});

test('loadNodes: LOGIN_PASSKEY_SIGN_IN is true or false without a config file, and conflicts with CONFIG_FILE', async () => {
  assert.equal((await loadNodes({})).login.passkeySignIn, true);
  assert.equal((await loadNodes({ LOGIN_PASSKEY_SIGN_IN: 'true' })).login.passkeySignIn, true);
  const off = await loadNodes({ LOGIN_PASSKEY_SIGN_IN: 'false', LOGIN_TRUSTED_PROXIES: '10.0.0.1' }, { storeUsers: true });
  assert.equal(off.login.passkeySignIn, false);
  assert.deepEqual(off.login.trustedProxies, ['10.0.0.1']);
  assert.equal(off.login.maxSessions, 1000);
  await assert.rejects(loadNodes({ LOGIN_PASSKEY_SIGN_IN: '' }), /LOGIN_PASSKEY_SIGN_IN is empty/);
  for (const bad of ['yes', 'no', '1', '0', 'TRUE', 'False', ' true']) await assert.rejects(loadNodes({ LOGIN_PASSKEY_SIGN_IN: bad }), /LOGIN_PASSKEY_SIGN_IN must be true or false/, bad);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  const file = path.join(dir, 'c.yaml');
  await fs.writeFile(file, ok);
  for (const value of ['false', 'true', '']) await assert.rejects(loadNodes({ CONFIG_FILE: file, LOGIN_PASSKEY_SIGN_IN: value }), /CONFIG_FILE replaces .*LOGIN_PASSKEY_SIGN_IN.*login\.passkey_sign_in/, JSON.stringify(value));
  assert.equal((await loadNodes({ CONFIG_FILE: file })).login.passkeySignIn, true);
});

test('config.example.yaml documents login.passkey_sign_in', async () => {
  const text = await fs.readFile(path.join(root, 'config.example.yaml'), 'utf8');
  assert.match(text, /^#   passkey_sign_in: true$/m);
  assert.match(text, /Sign in with a passkey/);
});

test('loadNodes: CONFIG_FILE replaces the variables and setting both is an error', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  const file = path.join(dir, 'c.yaml');
  await fs.writeFile(file, ok);
  assert.equal((await loadNodes({ CONFIG_FILE: file })).nodes.size, 3);
  await assert.rejects(loadNodes({ CONFIG_FILE: file, STATUS_TARGETS: 'a.test:1' }), /not both/);
  await assert.rejects(loadNodes({ CONFIG_FILE: file, STATS_URLS: 'a.test:1=https://a.test/s' }), /not both/);
  assert.equal((await loadNodes({ CONFIG_FILE: file, STATUS_TARGETS: '', STATS_URLS: '' })).targets.length, 3);
});

// ---- remote management keys ----

const MANAGE_SECRET = 'manage-secret-0123456789abcdef-ABCDEF';
const manageCfg = (node = '', second = '') => `nodes:\n  - address: a.test:1\n${node}  - address: b.test:1\n${second}`;
const manageNode = '    manage_url: http://10.0.0.2:8750\n    manage_secret_file: a.secret\n';

test('manage_url, manage_secret_file and manage_confirm_seconds are read per node', () => {
  const none = loadConfig(manageCfg());
  assert.equal(none.manage.size, 0);
  assert.equal(none.manageFiles.size, 0);
  const c = loadConfig(manageCfg(manageNode + '    manage_confirm_seconds: 900\n', '    manage_url: https://B.test:8750/\n    manage_secret_file: b.secret\n'));
  assert.deepEqual([...c.manage], [
    ['a.test:1', { url: 'http://10.0.0.2:8750', secret: null, confirmSeconds: 900 }],
    ['b.test:1', { url: 'https://b.test:8750', secret: null, confirmSeconds: 300 }],
  ]);
  assert.deepEqual([...c.manageFiles.values()].map((f) => f.path), ['a.secret', 'b.secret']);
  // Nothing about management is shown by the monitor.
  assert.equal(JSON.stringify([...c.nodes]).includes('manage'), false);
});

test('manage settings are checked strictly and the errors name the place', () => {
  const bad = (text, pattern) => assert.throws(() => loadConfig(text), (e) => pattern.test(e.message), pattern.source);
  bad(manageCfg('    manage_url: http://10.0.0.2:8750\n'), /nodes\[1\] needs both manage_url and manage_secret_file, or neither/);
  bad(manageCfg('    manage_secret_file: a.secret\n'), /needs both manage_url and manage_secret_file/);
  bad(manageCfg('    manage_confirm_seconds: 120\n'), /nodes\[1\] has manage_confirm_seconds but no manage_url/);
  for (const url of ['http://10.0.0.2:8750/manage', 'http://10.0.0.2:8750/?a=1', 'http://10.0.0.2:8750/?', 'http://10.0.0.2:8750#x', 'http://10.0.0.2:8750/#']) {
    bad(manageCfg(`    manage_url: "${url}"\n    manage_secret_file: a.secret\n`), /nodes\[1\]\.manage_url must be an address only/);
  }
  for (const url of ['ftp://10.0.0.2', 'not a url', 'http://user:pw@10.0.0.2:8750', 'http://example.org:8750', '5', 'null']) {
    bad(manageCfg(`    manage_url: "${url}"\n    manage_secret_file: a.secret\n`), /nodes\[1\]\.manage_url is not an http\(s\) URL|plain http/);
  }
  // The messages never repeat the URL (it could carry something private).
  assert.throws(() => loadConfig(manageCfg('    manage_url: http://user:pw@10.0.0.2:8750\n    manage_secret_file: a\n')), (e) => !/pw|10\.0\.0\.2/.test(e.message));
  bad(manageCfg('    manage_url: http://10.0.0.2:8750\n    manage_secret_file: 5\n'), /manage_secret_file must be a file path/);
  for (const v of ['59', '901', '60.5', '"120"', 'null', 'true']) {
    bad(manageCfg(`${manageNode}    manage_confirm_seconds: ${v}\n`), /nodes\[1\]\.manage_confirm_seconds must be a whole number from 60 to 900/);
  }
  assert.equal(loadConfig(manageCfg(`${manageNode}    manage_confirm_seconds: 60\n`)).manage.get('a.test:1').confirmSeconds, 60);
  // Management keys are for nodes only, not the top level.
  bad(`manage_url: http://10.0.0.2:8750\n${manageCfg()}`, /unknown key "manage_url"/);
});

test('manage_url over plain http takes the private ranges the node listens on (tunnels included) and refuses public addresses', () => {
  const urlOf = (url) => loadConfig(manageCfg(`    manage_url: "${url}"\n    manage_secret_file: a.secret\n`)).manage.get('a.test:1').url;
  // Loopback, RFC 1918, 100.64.0.0/10, fc00::/7 (WireGuard over IPv6), fe80::/10, and an
  // IPv4 private address written as IPv6.
  for (const [url, origin] of [
    ['http://127.0.0.1:8750', 'http://127.0.0.1:8750'],
    ['http://localhost:8750', 'http://localhost:8750'],
    ['http://10.0.0.2:8750', 'http://10.0.0.2:8750'],
    ['http://172.31.255.254:8750', 'http://172.31.255.254:8750'],
    ['http://192.168.4.4:8750', 'http://192.168.4.4:8750'],
    ['http://100.64.0.1:8750', 'http://100.64.0.1:8750'],
    ['http://100.101.102.103:8750', 'http://100.101.102.103:8750'],
    ['http://100.127.255.255:8750', 'http://100.127.255.255:8750'],
    ['http://[::1]:8750', 'http://[::1]:8750'],
    ['http://[fd7a:115c:a1e0::1]:8750', 'http://[fd7a:115c:a1e0::1]:8750'],
    ['http://[fc00::2]:8750', 'http://[fc00::2]:8750'],
    ['http://[fe80::1]:8750', 'http://[fe80::1]:8750'],
    ['http://[::ffff:10.0.0.2]:8750', 'http://[::ffff:a00:2]:8750'],
  ]) assert.equal(urlOf(url), origin, url);
  // Public addresses, ranges next to the private ones, host names, and the unspecified addresses.
  for (const url of ['http://8.8.8.8:8750', 'http://100.63.255.255:8750', 'http://100.128.0.1:8750', 'http://172.32.0.1:8750', 'http://169.254.1.1:8750', 'http://[2001:db8::1]:8750', 'http://[fec0::1]:8750', 'http://[::ffff:8.8.8.8]:8750', 'http://[::]:8750', 'http://0.0.0.0:8750', 'http://node.example.org:8750', 'http://10.0.0.2.nip.io:8750']) {
    assert.throws(() => urlOf(url), /nodes\[1\]\.manage_url uses plain http, which is only allowed for loopback and private addresses; use https/, url);
  }
  // https is taken for any host.
  assert.equal(urlOf('https://node.example.org:8750'), 'https://node.example.org:8750');
  // stats_url keeps the narrower list: its token is sent with every request.
  const statsOf = (url) => loadConfig(`nodes:\n  - address: a.test:1\n    stats_url: "${url}"\n`).statsUrls.get('a.test:1');
  for (const url of ['http://127.0.0.1:8080/stats', 'http://10.0.0.2:8080/stats', 'http://172.16.0.2:8080/stats', 'http://192.168.0.2:8080/stats', 'http://[::1]:8080/stats']) assert.equal(statsOf(url), url, url);
  for (const url of ['http://100.64.0.1:8080/stats', 'http://[fd7a:115c:a1e0::1]:8080/stats', 'http://[fe80::1]:8080/stats', 'http://8.8.8.8:8080/stats']) {
    assert.throws(() => statsOf(url), /stats_url uses plain http, which is only allowed for loopback and private addresses; use https/, url);
  }
});

async function manageDir(files, config) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-manage-'));
  for (const [name, text] of Object.entries(files)) await fs.writeFile(path.join(dir, name), text, { mode: 0o600 });
  await fs.writeFile(path.join(dir, 'config.yaml'), config);
  return path.join(dir, 'config.yaml');
}

test('the manage secret is read from its file, relative to the config, and trimmed', async () => {
  const file = await manageDir({ 'a.secret': `${MANAGE_SECRET}\n`, 'b.secret': `${MANAGE_SECRET}-other\r\n` }, manageCfg(manageNode, '    manage_url: https://b.test:8750\n    manage_secret_file: b.secret\n'));
  const c = await loadConfigFile(file);
  assert.deepEqual([...c.manage].map(([k, v]) => [k, v.secret]), [['a.test:1', MANAGE_SECRET], ['b.test:1', `${MANAGE_SECRET}-other`]]);
  assert.equal(c.manageFiles.size, 0);
  assert.deepEqual(c.warnings, []);
});

test('a manage secret file that the group or others can read or write stops the start, with a plain message that does not hold the secret', { skip: process.platform === 'win32' && 'POSIX modes only' }, async () => {
  for (const mode of [0o644, 0o640, 0o604, 0o444, 0o660, 0o620, 0o602, 0o622]) {
    const file = await manageDir({ 'a.secret': MANAGE_SECRET }, manageCfg(manageNode));
    await fs.chmod(path.join(path.dirname(file), 'a.secret'), mode);
    await assert.rejects(loadConfigFile(file), (e) => {
      assert.match(e.message, /nodes\[1\]\.manage_secret_file \(a\.secret\) can be read or changed by other users \(mode \d+\)/);
      assert.match(e.message, /chmod 600 a\.secret/);
      assert.equal(e.message.includes(MANAGE_SECRET), false);
      return true;
    }, mode.toString(8));
  }
  // Only the owner may read or write it: fine, without a warning.
  for (const mode of [0o600, 0o400, 0o700]) {
    const file = await manageDir({ 'a.secret': MANAGE_SECRET }, manageCfg(manageNode));
    await fs.chmod(path.join(path.dirname(file), 'a.secret'), mode);
    const c = await loadConfigFile(file);
    assert.equal(c.manage.get('a.test:1').secret, MANAGE_SECRET, mode.toString(8));
    assert.deepEqual(c.warnings, []);
  }
});

test('a stats token file that others can read still only gets a warning, while its manage secret is refused', { skip: process.platform === 'win32' && 'POSIX modes only' }, async () => {
  const cfg = manageCfg(`${manageNode}    stats_url: http://10.0.0.2:8080/stats\n    stats_token_file: t.token\n`);
  const file = await manageDir({ 'a.secret': MANAGE_SECRET, 't.token': `${MANAGE_SECRET}-stats\n` }, cfg);
  await fs.chmod(path.join(path.dirname(file), 't.token'), 0o644);
  const c = await loadConfigFile(file);
  assert.ok(c.warnings.some((w) => /stats_token_file/.test(w) && /can be read by other users/.test(w)));
  assert.equal(c.warnings.join('\n').includes(MANAGE_SECRET), false);
});

test('a bad manage secret stops the start and the message never holds it', async () => {
  const cases = [
    ['short', 'a'.repeat(31)],
    ['long', 'a'.repeat(257)],
    ['space', `${'a'.repeat(20)} ${'b'.repeat(20)}`],
    ['double quote', `${'a'.repeat(20)}"${'b'.repeat(20)}`],
    ['single quote', `${'a'.repeat(20)}'${'b'.repeat(20)}`],
    ['backslash', `${'a'.repeat(20)}\\${'b'.repeat(20)}`],
    ['tab inside', `${'a'.repeat(20)}\t${'b'.repeat(20)}`],
    ['non-ASCII', `${'a'.repeat(40)}é`],
    ['empty', ''],
  ];
  for (const [name, secret] of cases) {
    const file = await manageDir({ 'a.secret': secret }, manageCfg(manageNode));
    await assert.rejects(loadConfigFile(file), (e) => /the secret in nodes\[1\]\.manage_secret_file must be 32 to 256 printable ASCII characters without spaces, quotes or backslashes/.test(e.message) && (secret === '' || !e.message.includes(secret.slice(5, 30))), name);
  }
  for (const secret of ['a'.repeat(32), 'a'.repeat(256), '!#$%&()*+,-./:;<=>?@[]^_`{|}~'.padEnd(32, 'z')]) {
    const file = await manageDir({ 'a.secret': secret }, manageCfg(manageNode));
    assert.equal((await loadConfigFile(file)).manage.get('a.test:1').secret, secret);
  }
  const missing = await manageDir({}, manageCfg(manageNode));
  await assert.rejects(loadConfigFile(missing), /nodes\[1\]\.manage_secret_file cannot be read \(ENOENT\)/);
  const big = await manageDir({ 'a.secret': 'a'.repeat(2000) }, manageCfg(manageNode));
  await assert.rejects(loadConfigFile(big), /not a small file/);
});

test('two nodes with the same manage secret stop the start', async () => {
  const second = '    manage_url: http://10.0.0.3:8750\n    manage_secret_file: b.secret\n';
  const same = await manageDir({ 'a.secret': MANAGE_SECRET, 'b.secret': `${MANAGE_SECRET}\n` }, manageCfg(manageNode, second));
  await assert.rejects(loadConfigFile(same), (e) => /each node needs its own manage secret/.test(e.message) && /a\.test:1/.test(e.message) && /b\.test:1/.test(e.message) && !e.message.includes(MANAGE_SECRET));
  // One file for two nodes is the same secret.
  const shared = await manageDir({ 'a.secret': MANAGE_SECRET }, manageCfg(manageNode, '    manage_url: http://10.0.0.3:8750\n    manage_secret_file: a.secret\n'));
  await assert.rejects(loadConfigFile(shared), /each node needs its own manage secret/);
  const different = await manageDir({ 'a.secret': MANAGE_SECRET, 'b.secret': `${MANAGE_SECRET}2` }, manageCfg(manageNode, second));
  assert.equal((await loadConfigFile(different)).manage.size, 2);
});

test('a manage secret that is also a stats token stops the start, without naming it', async () => {
  const withToken = (where) => manageCfg(`${manageNode}    stats_url: http://10.0.0.2:8080/stats\n${where}`);
  // A node's own stats token, inline or from a file, and another node's token.
  const own = await manageDir({ 'a.secret': MANAGE_SECRET }, withToken(`    stats_token: ${MANAGE_SECRET}\n`));
  const fromFile = await manageDir({ 'a.secret': MANAGE_SECRET, 't.token': `${MANAGE_SECRET}\n` }, withToken('    stats_token_file: t.token\n'));
  const other = await manageDir({ 'a.secret': MANAGE_SECRET }, manageCfg(manageNode, `    stats_url: http://10.0.0.3:8080/stats\n    stats_token: ${MANAGE_SECRET}\n`));
  const top = await manageDir({ 'a.secret': MANAGE_SECRET }, `stats_token: ${MANAGE_SECRET}\n${withToken('')}`);
  for (const [name, file] of Object.entries({ own, fromFile, other, top })) {
    await assert.rejects(loadConfigFile(file), (e) => /manage secret of a\.test:1 is also used as a stats token/.test(e.message) && !e.message.includes(MANAGE_SECRET), name);
  }
  // A different stats token is fine.
  const fine = await manageDir({ 'a.secret': MANAGE_SECRET }, withToken(`    stats_token: ${MANAGE_SECRET}-stats\n`));
  assert.equal((await loadConfigFile(fine)).manage.get('a.test:1').secret, MANAGE_SECRET);
});

test('the environment variable mode has no management', async () => {
  const n = await loadNodes({ STATUS_TARGETS: 'a.test:1' });
  assert.equal(n.manage.size, 0);
  assert.equal(n.manageFiles.size, 0);
});

test('config.example.yaml documents the manage keys and still loads', async () => {
  const text = await fs.readFile(path.join(root, 'config.example.yaml'), 'utf8');
  for (const key of ['manage_url', 'manage_secret_file', 'manage_confirm_seconds']) assert.ok(text.includes(`# ${key}:`), key);
  // Uncommenting the example lines gives a config that loads.
  const on = text.replace(/^(\s*)# (manage_(?:url|secret_file|confirm_seconds):)/gm, '$1$2');
  const c = loadConfig(on);
  assert.deepEqual(c.manage.get('front.rns.rettui.dev:4242'), { url: 'http://10.200.0.2:8750', secret: null, confirmSeconds: 300 });
});
