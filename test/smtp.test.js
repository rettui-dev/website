import test from 'node:test';
import assert from 'node:assert/strict';
import { sendMail, buildMessage, headerText, address, oneLine, MAX_MESSAGE_BYTES } from '../lib/smtp.js';
import { fakeSmtp, TRUST } from './helpers/fake-smtp.js';

const base = (port, extra = {}) => ({ host: '127.0.0.1', port, security: 'starttls', from: 'status@example.org', to: ['ops@example.org'], ...extra });
const mail = { subject: '[rettui] Front is down', text: 'Front (front.test:4242) is down since 12:03 UTC.' };
const opts = { tlsOptions: TRUST, timeoutMs: 3000 };

function decodeBody(message) {
  const [head, body] = message.split('\r\n\r\n');
  return { head, text: Buffer.from(body.replace(/\r\n/g, ''), 'base64').toString('utf8') };
}

test('sends mail over STARTTLS after checking the certificate', async () => {
  const s = await fakeSmtp({ mode: 'starttls' });
  try {
    await sendMail(base(s.port), mail, opts);
    assert.deepEqual(s.log.commands, ['EHLO localhost', 'STARTTLS', 'EHLO localhost', 'MAIL FROM:<status@example.org>', 'RCPT TO:<ops@example.org>', 'DATA']);
    assert.equal(s.log.messages.length, 1);
    const { head, text } = decodeBody(s.log.messages[0]);
    assert.match(head, /^From: status@example\.org\r\nTo: ops@example\.org\r\nSubject: \[rettui\] Front is down\r\n/);
    assert.match(head, /Content-Type: text\/plain; charset=utf-8/);
    assert.equal(text, mail.text);
  } finally {
    await s.close();
  }
});

test('sends mail over SMTPS, to several recipients', async () => {
  const s = await fakeSmtp({ mode: 'tls' });
  try {
    await sendMail(base(s.port, { security: 'tls', to: ['a@example.org', 'b@example.org'] }), mail, opts);
    assert.deepEqual(s.log.commands.filter((c) => c.startsWith('RCPT')), ['RCPT TO:<a@example.org>', 'RCPT TO:<b@example.org>']);
    assert.ok(!s.log.commands.includes('STARTTLS'));
  } finally {
    await s.close();
  }
});

test('a certificate that is not trusted stops the mail before any credential is sent', async () => {
  for (const mode of ['tls', 'starttls']) {
    const s = await fakeSmtp({ mode, auth: { user: 'u', pass: 'secret-password' } });
    try {
      await assert.rejects(sendMail(base(s.port, { security: mode, username: 'u', password: 'secret-password' }), mail, { timeoutMs: 3000 }), (err) => {
        assert.equal(err.message, 'tls failed');
        return true;
      });
      assert.deepEqual(s.log.auths, []);
      assert.ok(!s.log.commands.includes('MAIL FROM:<status@example.org>'));
    } finally {
      await s.close();
    }
  }
});

test('STARTTLS is required: a server that does not offer it gets nothing', async () => {
  const s = await fakeSmtp({ mode: 'starttls', starttls: false, auth: { user: 'u', pass: 'p' } });
  try {
    await assert.rejects(sendMail(base(s.port, { username: 'u', password: 'p' }), mail, opts), { message: 'starttls not offered' });
    assert.deepEqual(s.log.auths, []);
  } finally {
    await s.close();
  }
});

test('AUTH PLAIN and AUTH LOGIN', async () => {
  const s = await fakeSmtp({ mode: 'starttls', auth: { user: 'alerts', pass: 'p@ss word' } });
  try {
    await sendMail(base(s.port, { username: 'alerts', password: 'p@ss word', auth: 'plain' }), mail, opts);
    assert.deepEqual(s.log.auths, [['plain', 'alerts', 'p@ss word']]);
    s.log.auths.length = 0;
    await sendMail(base(s.port, { username: 'alerts', password: 'p@ss word', auth: 'login' }), mail, opts);
    assert.deepEqual(s.log.auths, [['login', 'alerts'], ['login', 'p@ss word']]);
  } finally {
    await s.close();
  }
});

test('a wrong password fails with a code that does not repeat it', async () => {
  const s = await fakeSmtp({ mode: 'tls', auth: { user: 'u', pass: 'right' } });
  try {
    for (const auth of ['plain', 'login']) {
      await assert.rejects(sendMail(base(s.port, { security: 'tls', username: 'u', password: 'wrong-secret', auth }), mail, opts), (err) => {
        assert.equal(err.message, 'auth failed');
        assert.doesNotMatch(String(err.stack), /wrong-secret/);
        return true;
      });
    }
    assert.equal(s.log.messages.length, 0);
  } finally {
    await s.close();
  }
});

test('a refused recipient is a failure with the reply code only', async () => {
  const s = await fakeSmtp({ mode: 'tls', rcptReply: 550 });
  try {
    await assert.rejects(sendMail(base(s.port, { security: 'tls' }), mail, opts), { message: 'reply 550' });
    assert.equal(s.log.messages.length, 0);
  } finally {
    await s.close();
  }
});

test('a server that stops answering times out', async () => {
  const s = await fakeSmtp({ mode: 'tls', hang: true });
  try {
    const started = Date.now();
    await assert.rejects(sendMail(base(s.port, { security: 'tls' }), mail, { ...opts, timeoutMs: 300 }), { message: 'timeout' });
    assert.ok(Date.now() - started < 2000);
  } finally {
    await s.close();
  }
});

test('an oversized reply is refused', async () => {
  const s = await fakeSmtp({ mode: 'tls', bigReply: true });
  try {
    await assert.rejects(sendMail(base(s.port, { security: 'tls' }), mail, opts), { message: 'reply too large' });
  } finally {
    await s.close();
  }
});

test('a closed port fails quickly with a short code', async () => {
  const s = await fakeSmtp({ mode: 'starttls' });
  const { port } = s;
  await s.close();
  await assert.rejects(sendMail(base(port), mail, opts), { message: 'connect failed' });
  await assert.rejects(sendMail(base(port, { security: 'tls' }), mail, opts), { message: 'tls failed' });
});

test('a line break in any field is refused before anything is sent', async () => {
  const s = await fakeSmtp({ mode: 'starttls' });
  try {
    const cases = [
      [base(s.port, { from: 'a@example.org\r\nBcc: x@example.org' }), mail],
      [base(s.port, { to: ['ops@example.org\nBcc: x@example.org'] }), mail],
      [base(s.port, { to: ['ops@example.org>\r\nRCPT TO:<x@example.org'] }), mail],
      [base(s.port), { ...mail, subject: 'down\r\nBcc: x@example.org' }],
      [base(s.port, { username: 'u\r\nQUIT', password: 'p' }), mail],
      [base(s.port, { username: 'u', password: 'p\nQUIT' }), mail],
      [base(s.port, { from: 'a@example.org\0' }), mail],
    ];
    for (const [cfg, m] of cases) await assert.rejects(sendMail(cfg, m, opts), /line break|not an email address/);
    assert.deepEqual(s.log.commands, []);
  } finally {
    await s.close();
  }
});

test('address, oneLine and headerText', () => {
  assert.equal(address('a.b+c@example.org', 'to'), 'a.b+c@example.org');
  for (const bad of ['', 'a', 'a@', '@b.org', 'a b@example.org', 'a@b@c.org', '<a@b.org>', 'a@b.org,c@d.org', '"a"@b.org', 'a@b.org\r\n', 'a@-.org'.repeat(1) + '\n', `${'x'.repeat(300)}@b.org`]) {
    assert.throws(() => address(bad, 'to'), Error, JSON.stringify(bad));
  }
  assert.throws(() => address(5, 'to'), Error);
  assert.throws(() => oneLine('a\rb', 'x'), /line break/);
  assert.equal(headerText('Front is down', 's'), 'Front is down');
  assert.equal(headerText('Größe', 's'), `=?UTF-8?B?${Buffer.from('Größe').toString('base64')}?=`);
  assert.throws(() => headerText('a\nb', 's'), /line break/);
});

test('the message is cut at the size cap and has no bare dot lines', () => {
  const text = `${'.\n'.repeat(MAX_MESSAGE_BYTES)}end`;
  const m = buildMessage({ from: 'a@example.org', to: ['b@example.org'], subject: 's', text, id: 'id1', date: new Date(Date.UTC(2026, 10, 19, 12, 0)) });
  const body = m.split('\r\n\r\n')[1];
  assert.ok(Buffer.from(body.replace(/\r\n/g, ''), 'base64').length <= MAX_MESSAGE_BYTES);
  assert.ok(!/\r\n\./.test(m));
  assert.match(m, /Message-ID: <id1@example\.org>/);
  assert.match(m, /Date: Thu, 19 Nov 2026 12:00:00 \+0000/);
  assert.ok(m.endsWith('\r\n'));
});
