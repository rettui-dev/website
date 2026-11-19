import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { loadConfig, loadConfigFile, loadNodes, MAX_CHANNELS, MAX_RECIPIENTS } from '../lib/config.js';

const nodes = `
nodes:
  - address: a.test:4242
`;
const withAlerts = (alerts) => `${nodes}alerts:\n${alerts.replace(/^/gm, '  ')}\n`;
const bad = (alerts, pattern) => assert.throws(() => loadConfig(withAlerts(alerts)), (e) => e instanceof Error && pattern.test(e.message), alerts);
const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'website-'));

test('without an alerts section there are no alerts', () => {
  assert.equal(loadConfig(nodes).alerts, null);
});

test('a webhook channel with the defaults', () => {
  const c = loadConfig(withAlerts('channels:\n  - type: webhook\n    url: https://hooks.example/abc'));
  assert.deepEqual(c.alerts, {
    channels: [{ type: 'webhook', url: 'https://hooks.example/abc', format: 'generic' }],
    events: ['down', 'recovered'],
    cooldownMinutes: 15,
    repeatMinutes: 0,
  });
});

test('all the settings of both channel types', () => {
  const c = loadConfig(
    withAlerts(`
channels:
  - type: webhook
    url: http://127.0.0.1:8080/hook
    format: ntfy
    secret: 0123456789abcdef0123
  - type: webhook
    url: https://x.example/h
    format: slack
    secret_file: secrets/hook.secret
  - type: email
    host: Mail.Example.org
    security: tls
    username: alerts
    password_file: secrets/mail.pass
    auth: login
    from: status@example.org
    to: [ops@example.org, oncall@example.org]
events: [recovered]
cooldown_minutes: 0
repeat_minutes: 60
`),
  );
  const [a, b, m] = c.alerts.channels;
  assert.deepEqual(a, { type: 'webhook', url: 'http://127.0.0.1:8080/hook', format: 'ntfy', secret: '0123456789abcdef0123' });
  assert.deepEqual(b, { type: 'webhook', url: 'https://x.example/h', format: 'slack', secretFile: 'secrets/hook.secret' });
  assert.deepEqual(m, {
    type: 'email',
    host: 'mail.example.org',
    port: 465,
    security: 'tls',
    from: 'status@example.org',
    to: ['ops@example.org', 'oncall@example.org'],
    username: 'alerts',
    passwordFile: 'secrets/mail.pass',
    auth: 'login',
  });
  assert.deepEqual([c.alerts.events, c.alerts.cooldownMinutes, c.alerts.repeatMinutes], [['recovered'], 0, 60]);
});

test('an email channel without a login, and the default ports', () => {
  const c = loadConfig(withAlerts('channels:\n  - type: email\n    host: 10.0.0.5\n    from: a@example.org\n    to: [b@example.org]'));
  assert.deepEqual(c.alerts.channels[0], { type: 'email', host: '10.0.0.5', port: 587, security: 'starttls', from: 'a@example.org', to: ['b@example.org'] });
  const p = loadConfig(withAlerts('channels:\n  - type: email\n    host: m.example\n    port: 2525\n    from: a@example.org\n    to: [b@example.org]'));
  assert.equal(p.alerts.channels[0].port, 2525);
});

test('mistakes in the alerts section stop the start with a clear message', () => {
  const hook = 'channels:\n  - type: webhook\n    url: https://h.example/x\n';
  bad('events: [down]', /alerts\.channels must be a list of 1 to 4/);
  bad('channels: []', /alerts\.channels must be a list of 1 to 4/);
  bad('channels: x', /alerts\.channels must be a list/);
  bad(`${hook}unknown: 1`, /alerts has an unknown key "unknown"/);
  bad(`${hook}events: []`, /alerts\.events must be a list/);
  bad(`${hook}events: [down, down]`, /lists down twice/);
  bad(`${hook}events: [explode]`, /alerts\.events\[1\] must be one of down, recovered/);
  bad(`${hook}events: [announce_queue]`, /announce_queue is not available/);
  bad(`${hook}events: down`, /alerts\.events must be a list/);
  bad(`${hook}cooldown_minutes: -1`, /cooldown_minutes must be a whole number from 0 to 1440/);
  bad(`${hook}cooldown_minutes: 1.5`, /cooldown_minutes must be a whole number/);
  bad(`${hook}cooldown_minutes: 5000`, /cooldown_minutes must be a whole number/);
  bad(`${hook}repeat_minutes: 3`, /repeat_minutes must be 0 .* or at least 5/);
  bad(`${hook}repeat_minutes: x`, /repeat_minutes must be a whole number/);
  bad('channels:\n  - nope', /alerts\.channels\[1\] must be a map/);
  bad('channels:\n  - type: sms', /alerts\.channels\[1\]\.type must be webhook or email/);
  bad('channels:\n  - url: https://h.example/x', /alerts\.channels\[1\]\.type must be webhook or email/);
  assert.throws(() => loadConfig(`${nodes}alerts: x`), /"alerts" must be a map/);
});

test('webhook mistakes', () => {
  const w = (extra) => `channels:\n  - type: webhook\n${extra}`;
  bad(w('    secret: 0123456789abcdef0123'), /needs a url/);
  bad(w('    url: ftp://h.example/x'), /url is not an http\(s\) URL/);
  bad(w('    url: not a url'), /url is not an http\(s\) URL/);
  bad(w('    url: https://user:pw@h.example/x'), /url is not an http\(s\) URL without a user name or password/);
  bad(w('    url: https://user@h.example/x'), /without a user name or password/);
  bad(w('    url: http://hooks.example.com/x'), /plain http, which is only allowed for loopback and private addresses/);
  bad(w('    url: https://h.example/x\n    format: teams'), /format must be one of generic, ntfy, discord, slack/);
  bad(w('    url: https://h.example/x\n    secret: short'), /secret must be 16 to 256 printable characters/);
  bad(w('    url: https://h.example/x\n    secret: 0123456789abcdef0123\n    secret_file: s'), /has both secret and secret_file/);
  bad(w('    url: https://h.example/x\n    secret_file: ""'), /secret_file must be a file path/);
  bad(w('    url: https://h.example/x\n    bogus: 1'), /unknown key "bogus"/);
  bad(w(`    url: https://h.example/${'a'.repeat(2100)}`), /longer than 2048/);
  bad(w('    url: [https://h.example/x]'), /url is not an http\(s\) URL/);
});

test('private hosts may use plain http, public ones may not', () => {
  for (const host of ['localhost', '127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1']) {
    assert.doesNotThrow(() => loadConfig(withAlerts(`channels:\n  - type: webhook\n    url: http://${host}:9/x`)), host);
  }
  for (const host of ['8.8.8.8', '172.32.0.1', 'example.com']) {
    assert.throws(() => loadConfig(withAlerts(`channels:\n  - type: webhook\n    url: http://${host}/x`)), /plain http/, host);
  }
});

test('email mistakes', () => {
  const e = (extra) => `channels:\n  - type: email\n${extra}`;
  const ok = '    host: m.example\n    from: a@example.org\n    to: [b@example.org]';
  bad(e('    from: a@example.org\n    to: [b@example.org]'), /host must be the name of the mail server/);
  bad(e(ok.replace('m.example', 'a b')), /host must be the name/);
  bad(e(ok.replace('m.example', "'m.example\\r\\nX'").replace(/'/g, '"')), /host must be the name/);
  bad(e(ok + '\n    port: 0'), /port must be a whole number from 1 to 65535/);
  bad(e(ok + '\n    port: 70000'), /port must be a whole number/);
  bad(e(ok + '\n    security: none'), /security must be tls .* or starttls .*never sent unencrypted/);
  bad(e(ok + '\n    username: u'), /username but no password_file/);
  bad(e(ok + '\n    password_file: p'), /password_file or auth but no username/);
  bad(e(ok + '\n    auth: login'), /password_file or auth but no username/);
  bad(e(ok + '\n    username: u\n    password_file: p\n    auth: ntlm'), /auth must be plain or login/);
  bad(e(ok + '\n    username: ""\n    password_file: p'), /username must be 1 to 256/);
  bad(e(ok + '\n    username: "a\\nb"\n    password_file: p'), /username must be 1 to 256 characters without control/);
  bad(e(ok.replace('from: a@example.org', 'from: nobody')), /from must be an email address/);
  bad(e(ok.replace('from: a@example.org', 'from: "a@example.org\\r\\nBcc: x@example.org"')), /from must be an email address/);
  bad(e(ok.replace('from: a@example.org', 'from: "A <a@example.org>"')), /from must be an email address/);
  bad(e(ok.replace('[b@example.org]', '[]')), /to must be a list of 1 to 5/);
  bad(e(ok.replace('to: [b@example.org]', 'to: b@example.org')), /to must be a list of 1 to 5/);
  bad(e(ok.replace('[b@example.org]', '["b@example.org\\nBcc: x@example.org"]')), /to\[1\] must be an email address/);
  bad(e(ok.replace('[b@example.org]', `[${Array.from({ length: MAX_RECIPIENTS + 1 }, (_, i) => `u${i}@example.org`)}]`)), /to must be a list of 1 to 5/);
  bad(e(ok + '\n    extra: 1'), /unknown key "extra"/);
  bad(e(ok.replace('from: a@example.org', `from: ${'a'.repeat(250)}@example.org`)), /from must be an email address/);
});

test('there are at most four channels', () => {
  const one = '  - type: webhook\n    url: https://h.example/x';
  assert.doesNotThrow(() => loadConfig(withAlerts(`channels:\n${Array(MAX_CHANNELS).fill(one).join('\n')}`)));
  bad(`channels:\n${Array(MAX_CHANNELS + 1).fill(one).join('\n')}`, /1 to 4 channels/);
});

test('errors never repeat a URL, a secret, an address or a password', () => {
  const secrets = ['https://user:HUNTER2URL@h.example/TOKENPATH', 'SECRETSECRETSECRET', 'p4ssw0rd-in-the-file'];
  const cases = [
    `channels:\n  - type: webhook\n    url: ${secrets[0]}`,
    `channels:\n  - type: webhook\n    url: http://TOKENPATH.example.com/x`,
    `channels:\n  - type: webhook\n    url: https://h.example/TOKENPATH\n    secret: ${secrets[1]} nope`,
    `channels:\n  - type: webhook\n    url: https://h.example/TOKENPATH\n    secret: abcdefghijklmnopqrst\n    secret_file: TOKENPATH`,
    `channels:\n  - type: webhook\n    url: https://h.example/TOKENPATH\n    format: SECRETSECRETSECRET`,
    `channels:\n  - type: email\n    host: m.example\n    from: SECRETSECRETSECRET\n    to: [b@example.org]`,
    `channels:\n  - type: email\n    host: m.example\n    from: a@example.org\n    to: [SECRETSECRETSECRET]`,
    `channels:\n  - type: email\n    host: m.example\n    from: a@example.org\n    to: [b@example.org]\n    username: SECRETSECRETSECRET`,
    `channels:\n  - type: email\n    host: m.example\n    from: a@example.org\n    to: [b@example.org]\n    security: SECRETSECRETSECRET`,
  ];
  for (const alerts of cases) {
    try {
      loadConfig(withAlerts(alerts));
      assert.fail(`accepted: ${alerts}`);
    } catch (err) {
      assert.ok(!/HUNTER2URL|TOKENPATH|SECRETSECRETSECRET|p4ssw0rd/.test(err.message), err.message);
    }
  }
});

test('secret and password files are read relative to the config file, and only the secrets are kept', async () => {
  const dir = await tmp();
  await fs.mkdir(path.join(dir, 'secrets'));
  await fs.writeFile(path.join(dir, 'secrets', 'hook.secret'), 'file-secret-0123456789\n', { mode: 0o600 });
  await fs.writeFile(path.join(dir, 'secrets', 'mail.pass'), 'mail pass with spaces\n', { mode: 0o600 });
  await fs.writeFile(
    path.join(dir, 'config.yaml'),
    withAlerts(`
channels:
  - type: webhook
    url: https://h.example/x
    secret_file: secrets/hook.secret
  - type: email
    host: m.example
    from: a@example.org
    to: [b@example.org]
    username: u
    password_file: secrets/mail.pass
`),
  );
  const c = await loadConfigFile(path.join(dir, 'config.yaml'));
  const [hook, mail] = c.alerts.channels;
  assert.equal(hook.secret, 'file-secret-0123456789');
  assert.equal('secretFile' in hook, false);
  assert.equal(mail.password, 'mail pass with spaces');
  assert.equal('passwordFile' in mail, false);
  assert.deepEqual(c.warnings, []);
});

test('a bad secret file is an error that does not repeat its content', async () => {
  const dir = await tmp();
  const cfg = path.join(dir, 'config.yaml');
  const write = (alerts) => fs.writeFile(cfg, withAlerts(alerts));
  const hook = 'channels:\n  - type: webhook\n    url: https://h.example/x\n    secret_file: s';
  await write(hook);
  await assert.rejects(loadConfigFile(cfg), /alerts\.channels\[1\]\.secret_file cannot be read \(ENOENT\)/);
  await fs.writeFile(path.join(dir, 's'), 'too short');
  await assert.rejects(loadConfigFile(cfg), (e) => /the secret in alerts\.channels\[1\]\.secret_file must be 16 to 256/.test(e.message) && !e.message.includes('too short'));
  await fs.writeFile(path.join(dir, 's'), 'x'.repeat(5000));
  await assert.rejects(loadConfigFile(cfg), /secret_file is not a small file/);
  await fs.rm(path.join(dir, 's'));
  await fs.mkdir(path.join(dir, 's'));
  await assert.rejects(loadConfigFile(cfg), /is not a small file/);
  await write('channels:\n  - type: email\n    host: m.example\n    from: a@example.org\n    to: [b@example.org]\n    username: u\n    password_file: pw');
  await fs.writeFile(path.join(dir, 'pw'), 'bad\u0001pass');
  await assert.rejects(loadConfigFile(cfg), (e) => /the password in alerts\.channels\[1\]\.password_file must be 1 to 256/.test(e.message) && !e.message.includes('bad'));
  await fs.writeFile(path.join(dir, 'pw'), '\n');
  await assert.rejects(loadConfigFile(cfg), /password in .* must be 1 to 256/);
});

test('a world readable secret file gets a warning that does not name the secret', async () => {
  if (process.platform === 'win32') return;
  const dir = await tmp();
  await fs.writeFile(path.join(dir, 's'), 'file-secret-0123456789\n', { mode: 0o644 });
  await fs.chmod(path.join(dir, 's'), 0o644);
  await fs.writeFile(path.join(dir, 'config.yaml'), withAlerts('channels:\n  - type: webhook\n    url: https://h.example/x\n    secret_file: s'));
  const c = await loadConfigFile(path.join(dir, 'config.yaml'));
  assert.equal(c.warnings.length, 1);
  assert.match(c.warnings[0], /can be read by other users/);
  assert.ok(!c.warnings[0].includes('file-secret'));
});

test('the environment variables give no alerts, and the config file is the only way', async () => {
  const c = await loadNodes({ STATUS_TARGETS: 'a.test:1' });
  assert.equal(c.alerts, null);
  const dir = await tmp();
  await fs.writeFile(path.join(dir, 'config.yaml'), withAlerts('channels:\n  - type: webhook\n    url: https://h.example/x'));
  const f = await loadNodes({ CONFIG_FILE: path.join(dir, 'config.yaml') });
  assert.equal(f.alerts.channels.length, 1);
});

test('YAML tricks in the alerts section are refused like elsewhere', () => {
  assert.throws(() => loadConfig(`${nodes}alerts: &a\n  channels: *a\n`), /invalid YAML/);
  assert.throws(() => loadConfig(withAlerts('channels:\n  - type: webhook\n    url: https://h.example/x\n    url: https://h.example/y')), /invalid YAML/);
});
