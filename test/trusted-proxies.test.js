import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { loadConfig, loadConfigFile, loadNodes, parseTrustedProxiesEnv, proxyWarnings } from '../lib/config.js';
import { clientIp, hopAddress, proxyEntry, proxyMatcher, unreadableHop, untrustedProxy } from '../lib/login.js';

const HASH = '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc';
const USERS = `users:\n  - name: alice\n    password_hash: '${HASH}'\n`;
const NODES = 'nodes:\n  - address: a.test:1\n';
const yaml = (list) => `${USERS}login:\n  trusted_proxies: ${JSON.stringify(list)}\n${NODES}`;
const proxies = (list) => loadConfig(yaml(list)).login.trustedProxies;
const bad = (list, pattern) => assert.throws(() => loadConfig(yaml(list)), (e) => pattern.test(e.message), JSON.stringify(list));
const req = (peer, xff) => ({ socket: { remoteAddress: peer }, headers: xff === undefined ? {} : { 'x-forwarded-for': xff } });

test('trusted_proxies: networks in CIDR notation, mixed with addresses, in one spelling', () => {
  assert.deepEqual(proxies(['172.22.0.0/16', '10.0.0.0/8', 'fd00::/8', '127.0.0.1', '::1']), ['172.22.0.0/16', '10.0.0.0/8', 'fd00::/8', '127.0.0.1', '::1']);
  // IPv6 in any spelling; bits beyond the prefix are allowed and cleared.
  assert.deepEqual(proxies(['FD00:0:0:0::/8', '2001:DB8:0:0:0:0:0:0/32', '2001:db8:1:2:3:4:5:6/64']), ['fd00::/8', '2001:db8::/32', '2001:db8:1:2::/64']);
  assert.deepEqual(proxies(['172.22.9.5/16', '10.1.2.3/12', '192.168.1.255/31']), ['172.22.0.0/16', '10.0.0.0/12', '192.168.1.254/31']);
  // A full prefix is the single address.
  assert.deepEqual(proxies(['10.0.0.1/32', '0:0::1/128', 'FD00::0001/128']), ['10.0.0.1', '::1', 'fd00::1']);
  // IPv4-mapped IPv6 is IPv4, for an address and for a network of 96 bits or more.
  assert.deepEqual(proxies(['::ffff:10.0.0.1', '::ffff:172.22.0.0/112', '::FFFF:AC16:5/128', '::ffff:10.0.0.0/104']), ['10.0.0.1', '172.22.0.0/16', '172.22.0.5', '10.0.0.0/8']);
  assert.deepEqual(proxies([]), []);
  assert.equal(proxies(Array.from({ length: 16 }, (_, i) => `10.${i}.0.0/16`)).length, 16);
});

test('trusted_proxies: malformed entries are refused, naming the entry', () => {
  const cases = [
    '10.0.0.0/33', '::/129', '10.0.0.0/', '/8', '10.0.0.0/8/8', '10.0.0.0/-1', '10.0.0.0/+8', '10.0.0.0/08', '10.0.0.0/8.0', '10.0.0.0/0x8',
    '10.0.0.0 /8', '10.0.0.0/ 8', ' 10.0.0.0/8', '10.0.0/8', '256.0.0.0/8', '010.0.0.0/8', 'proxy.local/24', 'localhost/32', 'fe80::1%eth0/64',
    'fd00:::/8', '1:2:3:4:5:6:7:8:9/64', '10.0.0.1-10.0.0.9', '10.0.0.*', '', '10.0.0.0/1000', 'x'.repeat(80),
  ];
  for (const v of cases) bad(['127.0.0.1', v], /login\.trusted_proxies\[2\] is not an IP address or a network in CIDR notation/);
  for (const v of [8, null, true, ['10.0.0.0/8'], { a: 1 }]) bad([v], /trusted_proxies\[1\] is not an IP address or a network/);
  bad(Array.from({ length: 17 }, (_, i) => `10.${i}.0.0/16`), /login\.trusted_proxies must be a list of at most 16 IP addresses or networks/);
});

test('trusted_proxies: /0 is refused, as it would trust every address', () => {
  for (const v of ['0.0.0.0/0', '10.0.0.0/0', '::/0', '2001:db8::/0', '::ffff:0:0/96']) bad(['10.0.0.1', v], /login\.trusted_proxies\[2\] is .* which would trust every address/);
  assert.throws(() => parseTrustedProxiesEnv('0.0.0.0/0'), /LOGIN_TRUSTED_PROXIES: entry 1 is 0\.0\.0\.0\/0, which would trust every address/);
});

test('trusted_proxies: very wide networks are warned about at start, with the config file', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-proxies-'));
  const file = path.join(dir, 'c.yaml');
  await fs.writeFile(file, yaml(['10.0.0.0/8', '4.0.0.0/7', 'fd00::/16', '2000::/3', '127.0.0.1']));
  const c = await loadConfigFile(file, { storeUsers: false });
  const wide = c.warnings.filter((w) => w.includes('trusted_proxies'));
  assert.equal(wide.length, 2);
  assert.match(wide[0], /^WARNING: login\.trusted_proxies\[2\] \(4\.0\.0\.0\/7\) is a very wide network/);
  assert.match(wide[1], /^WARNING: login\.trusted_proxies\[4\] \(2000::\/3\) is a very wide network.*nothing untrusted/);
  await fs.writeFile(file, yaml(['10.0.0.0/8', 'fd00::/16']));
  assert.deepEqual((await loadConfigFile(file)).warnings, []);
  await fs.rm(dir, { recursive: true });
});

test('LOGIN_TRUSTED_PROXIES: networks, checked and warned about like trusted_proxies', async () => {
  const env = await loadNodes({ LOGIN_TRUSTED_PROXIES: '172.22.0.0/16, 10.0.0.1 ,FD00::/8,::ffff:192.168.0.0/112' }, { storeUsers: true });
  assert.deepEqual(env.login.trustedProxies, ['172.22.0.0/16', '10.0.0.1', 'fd00::/8', '192.168.0.0/16']);
  // fd00::/8 is shorter than /16, so it is warned about, as in the config file.
  assert.equal(env.warnings.length, 1);
  assert.match(env.warnings[0], /^WARNING: LOGIN_TRUSTED_PROXIES: entry 3 \(fd00::\/8\) is a very wide network/);
  assert.deepEqual((await loadNodes({ LOGIN_TRUSTED_PROXIES: '10.0.0.0/8,fd00:1::/16' }, { storeUsers: true })).warnings, []);
  const wide = await loadNodes({ LOGIN_TRUSTED_PROXIES: '10.0.0.1,0.0.0.0/1' }, { storeUsers: true });
  assert.match(wide.warnings.join('\n'), /^WARNING: LOGIN_TRUSTED_PROXIES: entry 2 \(0\.0\.0\.0\/1\) is a very wide network/);
  await assert.rejects(loadNodes({ LOGIN_TRUSTED_PROXIES: '10.0.0.1,10.0.0.0 /8' }), /LOGIN_TRUSTED_PROXIES: entry 2 is not an IP address or a network/);
  await assert.rejects(loadNodes({ LOGIN_TRUSTED_PROXIES: 'proxy.local/24' }), /entry 1 is not an IP address or a network/);
  await assert.rejects(loadNodes({ LOGIN_TRUSTED_PROXIES: '::/0' }), /entry 1 is ::\/0, which would trust every address/);
  await assert.rejects(loadNodes({ LOGIN_TRUSTED_PROXIES: Array.from({ length: 17 }, (_, i) => `10.${i}.0.0/16`).join(',') }), /at most 16/);
});

test('proxyEntry: family, prefix and spelling', () => {
  assert.deepEqual(
    [proxyEntry('172.22.0.0/16'), proxyEntry('fd00::/8'), proxyEntry('::ffff:10.0.0.0/104'), proxyEntry('10.0.0.1')].map((p) => [p.text, p.family, p.prefix, p.single]),
    [['172.22.0.0/16', 4, 16, false], ['fd00::/8', 6, 8, false], ['10.0.0.0/8', 4, 8, false], ['10.0.0.1', 4, 32, true]],
  );
  assert.equal(proxyEntry('fe80::1%ETH0').text, 'fe80::1%eth0', 'a single address keeps its zone, as before');
  assert.equal(proxyEntry(undefined), null);
});

test('proxyMatcher: the edges of a network, and /32 and /128 as single addresses', () => {
  const m = proxyMatcher(['172.22.0.0/16']);
  assert.equal(m.has('172.22.0.0'), true);
  assert.equal(m.has('172.22.255.255'), true);
  assert.equal(m.has('172.21.255.255'), false);
  assert.equal(m.has('172.23.0.0'), false);
  assert.equal(m.has('::ffff:172.22.0.5'), true, 'IPv4-mapped IPv6 is in an IPv4 network');
  assert.equal(m.has('::ffff:ac16:5'), true);
  assert.equal(m.has('::ac16:5'), false, 'IPv4-compatible is not mapped');
  assert.equal(m.has('2001:db8::1'), false);
  assert.equal(m.has('not an ip'), false);
  assert.equal(m.has(''), false);
  assert.equal(m.has(undefined), false);

  const odd = proxyMatcher(['10.1.2.3/12']);
  assert.equal(odd.has('10.0.0.0'), true);
  assert.equal(odd.has('10.15.255.255'), true);
  assert.equal(odd.has('10.16.0.0'), false);

  const one = proxyMatcher(['10.0.0.1/32', '::1/128']);
  assert.equal(one.has('10.0.0.1'), true);
  assert.equal(one.has('10.0.0.2'), false);
  assert.equal(one.has('10.0.0.0'), false);
  assert.equal(one.has('::1'), true);
  assert.equal(one.has('::2'), false);

  const v6 = proxyMatcher(['2001:db8:1:2::/64']);
  assert.equal(v6.has('2001:db8:1:2::'), true);
  assert.equal(v6.has('2001:db8:1:2:ffff:ffff:ffff:ffff'), true);
  assert.equal(v6.has('2001:0DB8:0001:0002:0000:0000:0000:0007'), true);
  assert.equal(v6.has('2001:db8:1:3::'), false);
  assert.equal(v6.has('2001:db8:1:1:ffff:ffff:ffff:ffff'), false);
  assert.equal(v6.has('fe80::1%eth0'), false);

  const odd6 = proxyMatcher(['fd00::/7', 'fe80::/10', '2001:db8::/33']);
  for (const ip of ['fc00::', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fe80::1%eth0', 'febf::1', '2001:db8:7fff::1', 'fd12::1.2.3.4']) assert.equal(odd6.has(ip), true, ip);
  for (const ip of ['fbff::1', 'fec0::1', '2001:db8:8000::1', '10.0.0.1']) assert.equal(odd6.has(ip), false, ip);

  // Matching is on the bits, not the text: no string prefix tests.
  const ten = proxyMatcher(['10.0.0.0/8']);
  assert.equal(ten.has('100.0.0.1'), false);
  assert.equal(ten.has('10.255.255.255'), true);
  assert.equal(ten.has('11.0.0.0'), false);
  assert.equal(ten.has('9.255.255.255'), false);
  assert.throws(() => proxyMatcher(['nope/8']), /not an IP address or network/);
});

test('clientIp with proxy networks: skips trusted hops from the right, ignores a spoofed header from an outsider', () => {
  const trusted = proxyMatcher(['172.22.0.0/16', 'fd00::/8', '127.0.0.1']);
  // An outsider sending its own X-Forwarded-For is taken at its address.
  assert.equal(clientIp(req('203.0.113.9', '1.2.3.4'), trusted), '203.0.113.9');
  assert.equal(clientIp(req('203.0.113.9', '172.22.0.5'), trusted), '203.0.113.9');
  assert.equal(clientIp(req('172.23.0.1', '1.2.3.4'), trusted), '172.23.0.1', 'just outside the network');
  // One proxy in the network.
  assert.equal(clientIp(req('172.22.0.5', '198.51.100.7'), trusted), '198.51.100.7');
  assert.equal(clientIp(req('::ffff:172.22.0.5', '198.51.100.7'), trusted), '198.51.100.7', 'IPv4-mapped peer');
  // Several hops, all trusted: the first untrusted address from the right; what the client wrote to the left is ignored.
  assert.equal(clientIp(req('127.0.0.1', '6.6.6.6, 198.51.100.7, 172.22.3.4, fd00::9, 172.22.0.2'), trusted), '198.51.100.7');
  assert.equal(clientIp(req('fd12::1', '2001:db8::5, ::ffff:172.22.1.1'), trusted), '2001:db8::5');
  // Every hop trusted: the peer. Garbage on the way: the peer.
  assert.equal(clientIp(req('172.22.0.5', '172.22.0.9, 127.0.0.1'), trusted), '172.22.0.5');
  assert.equal(clientIp(req('172.22.0.5', '1.2.3.4, garbage, 172.22.0.9'), trusted), '172.22.0.5');
  assert.equal(clientIp(req('172.22.0.5'), trusted), '172.22.0.5');
  // A peer in the network is not reported as an untrusted proxy; one outside it is.
  assert.equal(untrustedProxy(req('172.22.0.5', '1.2.3.4'), trusted), null);
  assert.equal(untrustedProxy(req('172.23.0.5', '1.2.3.4'), trusted), '172.23.0.5');
});

test('trusted_proxies: an IPv6 network holding every IPv4-mapped address is refused like /0', () => {
  for (const v of ['::/64', '::/80', '::fffe:0:0/95', '0::/16', '::/48', '::ffff:0:0/96']) bad(['10.0.0.1', v], /trusted_proxies\[2\] is .*(covers every IPv4 address|would trust every address)/);
  for (const v of ['::/64', '::/80', '::fffe:0:0/95', '0::/16']) bad([v], /covers every IPv4 address/);
  assert.throws(() => parseTrustedProxiesEnv('10.0.0.1,::/80'), /LOGIN_TRUSTED_PROXIES: entry 2 is ::\/80, which covers every IPv4 address/);
  // ::/81 and ::/96 hold no mapped address: ::ffff:0:0 has bit 80 set.
  assert.deepEqual(proxies(['::/81', '::/96']), ['::/81', '::/96']);
  const m = proxyMatcher(['::/81']);
  assert.equal(m.has('1.2.3.4'), false);
  assert.equal(m.has('::7fff:1:2'), true);
  // A mapped network of 97 to 104 bits is an IPv4 network shorter than /8, and is warned about as one.
  assert.deepEqual(proxies(['::ffff:0:0/100']), ['0.0.0.0/4']);
  assert.match(proxyWarnings(proxies(['::ffff:0:0/100']), (i) => `login.trusted_proxies[${i}]`).join(''), /^WARNING: login\.trusted_proxies\[1\] \(0\.0\.0\.0\/4\) is a very wide network/);
});

test('X-Forwarded-For hops with a port or brackets are read as the address', () => {
  const cases = [
    ['1.2.3.4:5678', '1.2.3.4'], [' 1.2.3.4:80 ', '1.2.3.4'], ['[2001:DB8::1]:443', '2001:db8::1'], ['[2001:db8::1]', '2001:db8::1'], ['[::ffff:1.2.3.4]:1', '1.2.3.4'],
    // Only those forms: anything else is left as it is, and stays not an address.
    ['1.2.3.4:', '1.2.3.4:'], ['1.2.3.4:123456', '1.2.3.4:123456'], ['[1.2.3.4]:80', '[1.2.3.4]:80'], ['2001:db8::1:443', '2001:db8::1:443'], ['[2001:db8::1]:x', '[2001:db8::1]:x'], ['[nope]:1', '[nope]:1'], ['host:80', 'host:80'],
  ];
  for (const [input, out] of cases) assert.equal(hopAddress(input), out, input);
  const trusted = proxyMatcher(['172.22.0.0/16']);
  assert.equal(clientIp(req('172.22.0.5', '198.51.100.7:5678'), trusted), '198.51.100.7');
  assert.equal(clientIp(req('172.22.0.5', '[2001:db8::7]:443, 172.22.0.9:80'), trusted), '2001:db8::7');
  assert.equal(clientIp(req('203.0.113.9', '198.51.100.7:5678'), trusted), '203.0.113.9', 'an outsider is still taken at its address');
  assert.equal(unreadableHop(req('172.22.0.5', '198.51.100.7:5678'), trusted), null);
  assert.equal(unreadableHop(req('172.22.0.5', 'unknown'), trusted), '172.22.0.5');
  assert.equal(unreadableHop(req('172.22.0.5', '1.2.3.4, client.example:80, 172.22.0.9'), trusted), '172.22.0.5');
  assert.equal(unreadableHop(req('172.22.0.5', 'garbage, 1.2.3.4'), trusted), null, 'the client is found before the garbage');
  assert.equal(unreadableHop(req('203.0.113.9', 'garbage'), trusted), null, 'not a trusted proxy');
  assert.equal(unreadableHop(req('172.22.0.5'), trusted), null);
});
