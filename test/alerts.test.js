import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { Alerter, alertText, alertSubject, spanText, utcTime, sendWebhook, webhookBody, createQueueWatch, createAlerter, appriseType, MAX_ATTEMPTS } from '../lib/alerts.js';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Monitor } from '../lib/monitor.js';
import { fakeSmtp, TRUST } from './helpers/fake-smtp.js';

const T0 = Date.UTC(2026, 10, 19, 12, 3, 0);
const MIN = 60_000;
const K = 'front.test:4242';
const down = (extra = {}) => ({ type: 'down', key: K, start: T0, end: null, at: T0 + 30_000, ...extra });
const back = (extra = {}) => ({ type: 'recovered', key: K, start: T0, end: T0 + 5 * MIN, at: T0 + 5 * MIN + 30_000, ...extra });
const SECRET = 'webhook-secret-0123456789';
const URL_SECRET = 'https://chat.example/hooks/TOKEN-IN-THE-PATH-123';

// A fetch that records requests and answers from a list of statuses (or errors).
function fakeFetch(answers = [200]) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    const a = answers[Math.min(calls.length - 1, answers.length - 1)];
    if (a instanceof Error) throw a;
    return new Response('x'.repeat(10), { status: a });
  };
  fn.calls = calls;
  return fn;
}

function make(extra = {}) {
  const logs = [];
  const fetchFn = extra.fetchFn ?? fakeFetch();
  const sleeps = [];
  const a = new Alerter({
    channels: [{ type: 'webhook', url: URL_SECRET, format: 'generic', secret: SECRET }],
    names: new Map([[K, 'Front']]),
    now: () => T0 + 30_000,
    fetchFn,
    sleep: async (ms) => void sleeps.push(ms),
    log: (m) => logs.push(m),
    ...extra,
  });
  return { a, logs, fetchFn, sleeps };
}

test('the words of an alert are plain and concrete', () => {
  assert.equal(alertText({ ...down(), name: null }), 'front.test:4242 is down since 12:03 UTC.');
  assert.equal(alertText({ ...down(), name: 'Front' }), 'Front (front.test:4242) is down since 12:03 UTC.');
  assert.equal(alertText({ ...back(), name: 'Front' }), 'Front (front.test:4242) is back up after 5m 00s (down since 12:03 UTC).');
  assert.equal(alertText({ ...down({ at: T0 + 90 * MIN, repeat: true }), name: null }), 'front.test:4242 is still down since 12:03 UTC (1h 30m).');
  // Another day shows the date.
  assert.equal(alertText({ ...down(), name: null }, T0 + 24 * 60 * MIN), 'front.test:4242 is down since 2026-11-19 12:03 UTC.');
  assert.equal(alertSubject({ ...down(), name: 'Front' }), '[rettui] Front is down');
  assert.equal(alertSubject({ ...back(), name: null }), '[rettui] front.test:4242 is back up');
});

test('the text shows the date only when the time is not on the day of the alerter clock', async () => {
  const texts = [];
  const mk = (now) => new Alerter({ channels: [{ type: 'webhook', url: 'https://x.test/h', format: 'generic' }], now: () => now, fetchFn: async (_u, init) => (texts.push(JSON.parse(init.body).message), new Response('')), log: () => {} });
  const sameDay = mk(T0 + 30_000);
  sameDay.notify(down());
  await sameDay.idle();
  const nextDay = mk(T0 + 24 * 60 * MIN);
  nextDay.notify(down());
  await nextDay.idle();
  assert.deepEqual(texts, ['front.test:4242 is down since 12:03 UTC.', 'front.test:4242 is down since 2026-11-19 12:03 UTC.']);
  // Midnight UTC is the edge between the two.
  const midnight = Date.UTC(2026, 10, 20);
  assert.equal(utcTime(midnight - 1, midnight), '2026-11-19 23:59 UTC');
  assert.equal(utcTime(midnight, midnight), '00:00 UTC');
});

test('spanText and utcTime', () => {
  assert.equal(spanText(0), '0s');
  assert.equal(spanText(-5), '0s');
  assert.equal(spanText(59_000), '59s');
  assert.equal(spanText(3_725_000), '1h 02m');
  assert.equal(spanText(200_000_000), '2d 7h');
  assert.equal(utcTime(T0, T0), '12:03 UTC');
});

test('a down and a recovery each send one alert, in the generic format', async () => {
  const { a, fetchFn, logs } = make();
  a.notify(down());
  a.notify(back());
  await a.idle();
  assert.equal(fetchFn.calls.length, 2);
  const first = fetchFn.calls[0];
  assert.equal(first.url, URL_SECRET);
  assert.equal(first.init.method, 'POST');
  assert.equal(first.init.redirect, 'error');
  assert.ok(first.init.signal instanceof AbortSignal);
  assert.deepEqual(JSON.parse(first.init.body), {
    event: 'down',
    host: K,
    name: 'Front',
    message: 'Front (front.test:4242) is down since 12:03 UTC.',
    since: new Date(T0).toISOString(),
    recoveredAt: null,
    sentAt: new Date(T0 + 30_000).toISOString(),
    durationSeconds: 30,
  });
  assert.equal(JSON.parse(fetchFn.calls[1].init.body).event, 'recovered');
  assert.deepEqual(logs, []);
});

test('the signature is the HMAC-SHA256 of the body', async () => {
  const { a, fetchFn } = make();
  a.notify(down());
  await a.idle();
  const { body, headers } = fetchFn.calls[0].init;
  // The signed text is "<unix seconds>.<body>", so a captured request cannot be replayed with a fresh time.
  assert.equal(headers['X-Rettui-Timestamp'], String(Math.floor((T0 + 30_000) / 1000)));
  const want = crypto.createHmac('sha256', SECRET).update(`${headers['X-Rettui-Timestamp']}.${body}`).digest('hex');
  assert.equal(headers['X-Rettui-Signature'], `sha256=${want}`);
  assert.notEqual(headers['X-Rettui-Signature'], `sha256=${crypto.createHmac('sha256', SECRET).update(body).digest('hex')}`);
  assert.equal(headers['Content-Type'], 'application/json');
  // Without a secret there is no signature header.
  const plain = make({ channels: [{ type: 'webhook', url: URL_SECRET, format: 'generic' }] });
  plain.a.notify(down());
  await plain.a.idle();
  assert.equal('X-Rettui-Signature' in plain.fetchFn.calls[0].init.headers, false);
  assert.equal('X-Rettui-Timestamp' in plain.fetchFn.calls[0].init.headers, false);
});

test('the other formats', () => {
  const e = { ...down(), name: 'Front' };
  const text = alertText(e);
  assert.deepEqual(JSON.parse(webhookBody('slack', e, text)), { text });
  assert.deepEqual(JSON.parse(webhookBody('discord', e, text)), { content: text });
  assert.equal(webhookBody('ntfy', e, text), text);
  assert.equal(JSON.parse(webhookBody('generic', { ...e, repeat: true }, text)).event, 'still_down');
});

test('apprise gets title, body and type, and the type follows the event', async () => {
  const cases = [
    [{ ...down(), name: 'Front' }, 'failure', '[rettui] Front is down'],
    [{ ...down({ repeat: true }), name: 'Front' }, 'failure', '[rettui] Front is down'],
    [{ ...back(), name: 'Front' }, 'success', '[rettui] Front is back up'],
    [{ type: 'queue_full', key: K, name: 'Front', start: T0, end: null, at: T0, queued: 4096 }, 'warning', '[rettui] Front announce queue is full'],
    [{ type: 'queue_cleared', key: K, name: 'Front', start: T0, end: T0 + MIN, at: T0 + MIN }, 'success', '[rettui] Front announce queue is clear'],
  ];
  for (const [event, type, title] of cases) {
    const text = alertText(event);
    assert.equal(appriseType(event), type);
    // Exactly these three fields: nothing of the channel or the node's address beyond the text goes along.
    assert.deepEqual(JSON.parse(webhookBody('apprise', event, text)), { title, body: text, type });
  }
});

test('an apprise channel posts JSON to its url, signed when it has a secret, and leaks nothing', async () => {
  const url = 'http://172.28.0.20:8000/notify/KEY-IN-THE-PATH';
  const { a, fetchFn, logs } = make({ channels: [{ type: 'webhook', url, format: 'apprise', secret: SECRET }] });
  a.notify({ ...down(), name: 'Front' });
  await a.idle();
  const { url: sent, init } = fetchFn.calls[0];
  assert.equal(sent, url);
  assert.equal(init.method, 'POST');
  assert.equal(init.redirect, 'error');
  assert.equal(init.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(init.body), { title: '[rettui] Front is down', body: 'Front (front.test:4242) is down since 12:03 UTC.', type: 'failure' });
  const ts = init.headers['X-Rettui-Timestamp'];
  assert.equal(ts, String((T0 + 30_000) / 1000));
  assert.equal(init.headers['X-Rettui-Signature'], `sha256=${crypto.createHmac('sha256', SECRET).update(`${ts}.${init.body}`).digest('hex')}`);
  assert.equal(init.body.includes(SECRET), false);
  // Without a secret there are no signature headers.
  const plain = make({ channels: [{ type: 'webhook', url, format: 'apprise' }] });
  plain.a.notify(down());
  await plain.a.idle();
  assert.equal('X-Rettui-Signature' in plain.fetchFn.calls[0].init.headers, false);
  // A failure is logged without the address, the key in it or the secret.
  const bad = make({ channels: [{ type: 'webhook', url, format: 'apprise', secret: SECRET }], fetchFn: fakeFetch([404]) });
  bad.a.notify(down());
  await bad.a.idle();
  assert.equal(bad.logs.length, 1);
  assert.match(bad.logs[0], /failed \(http 404\), giving up/);
  for (const line of [...logs, ...bad.logs]) assert.doesNotMatch(line, /KEY-IN-THE-PATH|172\.28|webhook-secret/);
});

test('ntfy gets plain text and fixed ASCII header words, even for a name with other characters', async () => {
  const fetchFn = fakeFetch();
  const r = await sendWebhook({ url: 'https://ntfy.example/topic', format: 'ntfy' }, { ...down(), name: 'Zürich ✓' }, 'Zürich ✓ is down', { fetchFn });
  assert.equal(r.ok, true);
  const { headers, body } = fetchFn.calls[0].init;
  assert.equal(body, 'Zürich ✓ is down');
  assert.match(headers['Content-Type'], /^text\/plain/);
  assert.equal(headers.Title, 'Entry point is down');
  for (const v of Object.values(headers)) assert.match(v, /^[\x20-\x7e]*$/);
});

test('flapping: a second down inside the cooldown is not announced, nor its recovery', async () => {
  const { a, fetchFn } = make({ cooldownMs: 15 * MIN });
  a.notify(down());
  a.notify(back());
  // Down again 3 minutes after the first alert.
  a.notify(down({ start: T0 + 6 * MIN, at: T0 + 7 * MIN }));
  a.notify(back({ start: T0 + 6 * MIN, end: T0 + 9 * MIN, at: T0 + 10 * MIN }));
  await a.idle();
  assert.equal(fetchFn.calls.length, 2);
  // Past the cooldown it is announced again.
  a.notify(down({ start: T0 + 20 * MIN, at: T0 + 21 * MIN }));
  a.notify(back({ start: T0 + 20 * MIN, end: T0 + 25 * MIN, at: T0 + 26 * MIN }));
  await a.idle();
  assert.equal(fetchFn.calls.length, 4);
});

test('a recovery is always sent for an announced incident, and for a node the alerter has not seen go down', async () => {
  const { a, fetchFn } = make({ cooldownMs: 0 });
  a.notify(back());
  await a.idle();
  assert.equal(fetchFn.calls.length, 1);
});

test('a cooldown of 0 announces every incident', async () => {
  const { a, fetchFn } = make({ cooldownMs: 0 });
  for (let i = 0; i < 3; i++) {
    a.notify(down({ at: T0 + i * MIN }));
    a.notify(back({ at: T0 + i * MIN + 1 }));
  }
  await a.idle();
  assert.equal(fetchFn.calls.length, 6);
});

test('only the configured events are sent', async () => {
  const { a, fetchFn } = make({ events: ['down'] });
  a.notify(down());
  a.notify(back());
  await a.idle();
  assert.equal(fetchFn.calls.length, 1);
  assert.equal(JSON.parse(fetchFn.calls[0].init.body).event, 'down');
  const rec = make({ events: ['recovered'] });
  rec.a.notify(down());
  rec.a.notify(back());
  await rec.a.idle();
  assert.equal(rec.fetchFn.calls.length, 1);
});

test('reminders come only with repeat_minutes, for an announced incident', async () => {
  const { a, fetchFn } = make({ repeatMs: 30 * MIN });
  a.notify(down());
  a.remind([[K, T0]], T0 + 10 * MIN);
  await a.idle();
  assert.equal(fetchFn.calls.length, 1);
  a.remind([[K, T0]], T0 + 31 * MIN);
  a.remind([[K, T0]], T0 + 32 * MIN);
  await a.idle();
  assert.equal(fetchFn.calls.length, 2);
  assert.equal(JSON.parse(fetchFn.calls[1].init.body).event, 'still_down');
  a.remind([[K, T0]], T0 + 62 * MIN);
  await a.idle();
  assert.equal(fetchFn.calls.length, 3);
  // Unknown nodes get no reminder, and the default is none.
  a.remind([['other.test:1', T0]], T0 + 999 * MIN);
  const off = make();
  off.a.notify(down());
  off.a.remind([[K, T0]], T0 + 999 * MIN);
  await Promise.all([a.idle(), off.a.idle()]);
  assert.equal(fetchFn.calls.length, 3);
  assert.equal(off.fetchFn.calls.length, 1);
});

test('a failed send is retried with a growing wait and then given up, without secrets in the log', async () => {
  const { a, fetchFn, logs, sleeps } = make({ fetchFn: fakeFetch([500, new TypeError(`fetch failed ${URL_SECRET}`), 503]) });
  a.notify(down());
  await a.idle();
  assert.equal(fetchFn.calls.length, MAX_ATTEMPTS);
  assert.deepEqual(sleeps, [5000, 30_000]);
  assert.equal(logs.length, 3);
  assert.match(logs[0], /webhook channel 1 failed \(http 500\), try 2 of 3 follows/);
  assert.match(logs[1], /failed \(network\)/);
  assert.match(logs[2], /failed \(http 503\), giving up/);
  const all = logs.join('\n');
  assert.ok(!all.includes(SECRET) && !all.includes('TOKEN-IN-THE-PATH') && !all.includes('chat.example'));
});

test('a retry that works stops retrying', async () => {
  const { a, fetchFn, logs } = make({ fetchFn: fakeFetch([502, 200]) });
  a.notify(down());
  await a.idle();
  assert.equal(fetchFn.calls.length, 2);
  assert.equal(logs.length, 1);
});

test('a client error is not retried; 429 and 408 are', async () => {
  const { a, fetchFn, logs } = make({ fetchFn: fakeFetch([404]) });
  a.notify(down());
  await a.idle();
  assert.equal(fetchFn.calls.length, 1);
  assert.match(logs[0], /http 404\), giving up/);
  for (const code of [429, 408]) {
    const x = make({ fetchFn: fakeFetch([code, 200]) });
    x.a.notify(down());
    await x.a.idle();
    assert.equal(x.fetchFn.calls.length, 2, String(code));
  }
});

test('a redirect is an error, a timeout is reported as a timeout', async () => {
  const redirect = await sendWebhook({ url: URL_SECRET, format: 'generic' }, down(), 'x', { fetchFn: async () => { throw new TypeError('redirect'); } });
  assert.deepEqual(redirect, { ok: false, error: 'network', retry: true });
  const slow = await sendWebhook({ url: URL_SECRET, format: 'generic' }, down(), 'x', { fetchFn: async () => { throw Object.assign(new Error('t'), { name: 'TimeoutError' }); } });
  assert.deepEqual(slow, { ok: false, error: 'timeout', retry: true });
});

test('sending never blocks notify and a throwing fetch does not escape', async () => {
  const { a, logs } = make({ fetchFn: async () => { throw new Error(`boom ${SECRET}`); } });
  const before = Date.now();
  a.notify(down());
  assert.ok(Date.now() - before < 50);
  assert.doesNotThrow(() => a.notify({ type: 'down' }));
  assert.doesNotThrow(() => a.notify(null));
  await a.idle();
  assert.ok(!logs.join('\n').includes(SECRET));
});

test('the queue is bounded and drops the oldest alert', async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const calls = [];
  const fetchFn = async (url, init) => {
    calls.push(JSON.parse(init.body).host);
    await gate;
    return new Response('', { status: 200 });
  };
  const { a, logs } = make({ fetchFn, maxQueue: 3, cooldownMs: 0 });
  for (let i = 0; i < 10; i++) a.notify(down({ key: `n${i}.test:1` }));
  // Two are being sent, three wait: five of the ten were not kept.
  assert.equal(a.queued, 3);
  assert.equal(logs.filter((l) => /queue is full/.test(l)).length, 5);
  release();
  await a.idle();
  assert.deepEqual(calls, ['n0.test:1', 'n1.test:1', 'n7.test:1', 'n8.test:1', 'n9.test:1']);
});

test('every channel gets every alert, and a failing channel does not stop the other', async () => {
  const s = await fakeSmtp({ mode: 'tls' });
  try {
    const fetchFn = fakeFetch([500]);
    const { a, logs } = make({
      fetchFn,
      retryDelays: [0, 0],
      channels: [
        { type: 'webhook', url: URL_SECRET, format: 'generic' },
        { type: 'email', host: '127.0.0.1', port: s.port, security: 'tls', from: 'status@example.org', to: ['ops@example.org'], username: 'u', password: 'mail-password-xyz', auth: 'plain' },
      ],
      mailOptions: { tlsOptions: TRUST, timeoutMs: 3000 },
    });
    a.notify(down());
    await a.idle();
    assert.equal(fetchFn.calls.length, 3);
    // The mail server wants a login this channel gets wrong: reported once, not retried.
    assert.ok(logs.some((l) => /email channel 2 failed \(smtp /.test(l)));
    assert.ok(!logs.join('\n').includes('mail-password-xyz'));
  } finally {
    await s.close();
  }
});

test('email alerts carry the plain text and the subject', async () => {
  const s = await fakeSmtp({ mode: 'starttls', auth: { user: 'u', pass: 'mail-password-xyz' } });
  try {
    const { a, logs } = make({
      channels: [{ type: 'email', host: '127.0.0.1', port: s.port, security: 'starttls', from: 'status@example.org', to: ['ops@example.org'], username: 'u', password: 'mail-password-xyz', auth: 'login' }],
      mailOptions: { tlsOptions: TRUST, timeoutMs: 3000 },
    });
    a.notify(down());
    await a.idle();
    assert.deepEqual(logs, []);
    assert.equal(s.log.messages.length, 1);
    const [head, body] = s.log.messages[0].split('\r\n\r\n');
    assert.match(head, /Subject: \[rettui\] Front is down/);
    assert.equal(Buffer.from(body.replace(/\r\n/g, ''), 'base64').toString(), 'Front (front.test:4242) is down since 12:03 UTC.');
  } finally {
    await s.close();
  }
});

test('a mail failure that cannot get better is not retried', async () => {
  let n = 0;
  const { a, logs } = make({
    channels: [{ type: 'email', host: 'x.test', port: 1, security: 'tls', from: 'a@example.org', to: ['b@example.org'] }],
    mailFn: async () => {
      n++;
      throw new Error('reply 550');
    },
  });
  a.notify(down());
  await a.idle();
  assert.equal(n, 1);
  assert.match(logs[0], /smtp reply 550\), giving up/);
  // An unknown error text is not echoed.
  const odd = make({ channels: [{ type: 'email', host: 'x.test', port: 1, security: 'tls', from: 'a@example.org', to: ['b@example.org'] }], mailFn: async () => { throw new Error(`secret ${SECRET}`); } });
  odd.a.notify(down());
  await odd.a.idle();
  assert.ok(!odd.logs.join('\n').includes(SECRET));
});

test('the alerter shows no channel in a dump or JSON', () => {
  const { a } = make();
  const text = JSON.stringify(a) + JSON.stringify(Object.entries(a)) + String(Object.getOwnPropertyNames(a));
  assert.ok(!text.includes(SECRET) && !text.includes('TOKEN-IN-THE-PATH'));
  assert.equal(JSON.stringify(createAlerter(null)), 'null');
});

test('stop drops what is waiting', async () => {
  const { a, fetchFn } = make({ maxQueue: 50 });
  a.stop();
  a.notify(down());
  await a.idle();
  assert.equal(fetchFn.calls.length, 0);
});

test('createAlerter uses the config settings and the node names', async () => {
  const fetchFn = fakeFetch();
  const a = createAlerter(
    { channels: [{ type: 'webhook', url: 'https://x.test/h', format: 'generic' }], events: ['down'], cooldownMinutes: 1, repeatMinutes: 0 },
    new Map([[K, { name: 'Front' }], ['b.test:1', { name: null }]]),
    { fetchFn, now: () => T0 },
  );
  a.notify(down());
  await a.idle();
  assert.equal(JSON.parse(fetchFn.calls[0].init.body).name, 'Front');
});

// The real webhook path against a server on loopback.
async function hookServer(handler) {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
      handler(req, res);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}/hook`, seen, close: () => new Promise((r) => (server.closeAllConnections(), server.close(r))) };
}

test('a real webhook gets a signed POST', async () => {
  const s = await hookServer((_req, res) => res.end('ok'));
  try {
    const r = await sendWebhook({ url: s.url, format: 'generic', secret: SECRET }, { ...down(), name: 'Front' }, 'Front is down');
    assert.deepEqual(r, { ok: true });
    const got = s.seen[0];
    assert.equal(got.method, 'POST');
    assert.equal(got.url, '/hook');
    const ts = got.headers['x-rettui-timestamp'];
    assert.match(ts, /^\d{10}$/);
    assert.ok(Math.abs(Number(ts) - Date.now() / 1000) < 5);
    assert.equal(got.headers['x-rettui-signature'], `sha256=${crypto.createHmac('sha256', SECRET).update(`${ts}.${got.body}`).digest('hex')}`);
    assert.equal(JSON.parse(got.body).message, 'Front is down');
  } finally {
    await s.close();
  }
});

test('a real webhook that redirects is not followed', async () => {
  const target = await hookServer((_req, res) => res.end('ok'));
  const s = await hookServer((_req, res) => {
    res.writeHead(302, { Location: target.url });
    res.end();
  });
  try {
    const r = await sendWebhook({ url: s.url, format: 'generic', secret: SECRET }, down(), 'x');
    assert.equal(r.ok, false);
    assert.equal(target.seen.length, 0);
  } finally {
    await s.close();
    await target.close();
  }
});

test('a real webhook that is slow times out, and a huge answer is not read', async () => {
  const slow = await hookServer(() => {});
  const big = await hookServer((_req, res) => {
    res.writeHead(200, { 'Content-Length': String(50 * 1024 * 1024) });
    res.write(Buffer.alloc(64 * 1024));
    // The rest never comes: reading it would hang.
  });
  try {
    const t = await sendWebhook({ url: slow.url, format: 'generic' }, down(), 'x', { timeoutMs: 200 });
    assert.deepEqual(t, { ok: false, error: 'timeout', retry: true });
    const b = await sendWebhook({ url: big.url, format: 'generic' }, down(), 'x', { timeoutMs: 2000 });
    assert.deepEqual(b, { ok: true });
  } finally {
    await slow.close();
    await big.close();
  }
});

test('a closed port is a network error', async () => {
  const s = await hookServer((_req, res) => res.end());
  const { url } = s;
  await s.close();
  assert.deepEqual(await sendWebhook({ url, format: 'generic' }, down(), 'x', { timeoutMs: 1000 }), { ok: false, error: 'network', retry: true });
});

test('announce queue rule: full for N samples in a row, once, then cleared', () => {
  const w = createQueueWatch(3);
  assert.equal(w.observe(K, 10, 10), null);
  assert.equal(w.observe(K, 12, 10), null);
  assert.equal(w.observe(K, 10, 10), 'full');
  assert.equal(w.observe(K, 10, 10), null);
  assert.equal(w.observe(K, 9, 10), 'cleared');
  assert.equal(w.observe(K, 9, 10), null);
});

test('announce queue rule: a sample below capacity or a missed one breaks the run', () => {
  const w = createQueueWatch(3);
  w.observe(K, 10, 10);
  w.observe(K, 10, 10);
  assert.equal(w.observe(K, 5, 10), null);
  w.observe(K, 10, 10);
  w.observe(K, 10, 10);
  w.miss(K);
  assert.equal(w.observe(K, 10, 10), null);
  assert.equal(w.observe(K, 10, 10), null);
  assert.equal(w.observe(K, 10, 10), 'full');
  // Nodes are independent.
  assert.equal(w.observe('b.test:1', 10, 10), null);
});

test('announce queue rule ignores numbers that make no sense', () => {
  const w = createQueueWatch(1);
  for (const [len, cap] of [[NaN, 10], [10, 0], [10, -1], [-1, 10], ['10', 10], [10, undefined], [Infinity, 10]]) assert.equal(w.observe(K, len, cap), null);
  assert.equal(w.observe(K, 1, 1), 'full');
  assert.doesNotThrow(() => w.miss('never.seen:1'));
});

function queueAlerter(extra = {}) {
  const f = fakeFetch([200, 200, 200, 200, 200, 200]);
  let now = T0;
  const a = new Alerter({ channels: [{ type: 'webhook', url: 'https://h.example/x', format: 'generic' }], events: ['announce_queue'], fetchFn: f, now: () => now, retryDelays: [0], ...extra });
  return { a, f, at: (t) => (now = t) };
}

test('queue alert: full for N samples in a row alerts once, and a recovery follows', async () => {
  const { a, f } = queueAlerter({ queueSamples: 3, names: new Map([[K, 'Front']]) });
  const full = { full: true, queued: 4096 };
  a.observeQueue(K, full, T0);
  a.observeQueue(K, full, T0 + 30_000);
  assert.equal(a.queued, 0);
  a.observeQueue(K, full, T0 + 60_000);
  a.observeQueue(K, full, T0 + 90_000);
  await a.idle();
  assert.equal(f.calls.length, 1);
  const body = JSON.parse(f.calls[0].init.body);
  assert.equal(body.event, 'announce_queue_full');
  assert.match(body.message, /Front \(front\.test:4242\) has a full announce queue \(4096 waiting\)/);
  a.observeQueue(K, { full: false, queued: 3 }, T0 + 120_000);
  await a.idle();
  assert.equal(f.calls.length, 2);
  const back = JSON.parse(f.calls[1].init.body);
  assert.equal(back.event, 'announce_queue_cleared');
  // Counted from the first full sample, not from the alert three samples later.
  assert.equal(back.durationSeconds, 120);
  assert.match(back.message, /no longer full \(it was full for 2m 00s\)/);
});

test('queue alert: off unless announce_queue is in events, and a missed sample breaks the run', async () => {
  const off = queueAlerter({ events: ['down', 'recovered'], queueSamples: 1 });
  off.a.observeQueue(K, { full: true, queued: 1 }, T0);
  await off.a.idle();
  assert.equal(off.f.calls.length, 0);
  const { a, f } = queueAlerter({ queueSamples: 2 });
  a.observeQueue(K, { full: true }, T0);
  a.queueMissed(K);
  a.observeQueue(K, { full: true }, T0 + 1);
  await a.idle();
  assert.equal(f.calls.length, 0);
  a.observeQueue(K, { full: true }, T0 + 2);
  await a.idle();
  assert.equal(f.calls.length, 1);
});

test('queue alert: the cooldown keeps a queue that fills again soon quiet, with its clearing', async () => {
  const { a, f } = queueAlerter({ queueSamples: 1, cooldownMs: 15 * MIN });
  const full = { full: true };
  a.observeQueue(K, full, T0);
  a.observeQueue(K, { full: false }, T0 + MIN);
  a.observeQueue(K, full, T0 + 2 * MIN);
  a.observeQueue(K, { full: false }, T0 + 3 * MIN);
  await a.idle();
  assert.equal(f.calls.length, 2);
  // After the cooldown it is announced again.
  a.observeQueue(K, full, T0 + 20 * MIN);
  await a.idle();
  assert.equal(f.calls.length, 3);
});

test('queue alert: texts, subjects and ntfy headers', () => {
  const e = { type: 'queue_full', key: K, name: null, start: T0, end: null, at: T0, queued: 'x' };
  assert.equal(alertText(e), `${K} has a full announce queue: an interface is at its limit and drops new announces.`);
  assert.equal(alertSubject(e), `[rettui] ${K} announce queue is full`);
  assert.equal(alertSubject({ ...e, type: 'queue_cleared' }), `[rettui] ${K} announce queue is clear`);
});

test('a node that flaps once and then stays down is announced when the cooldown has passed', async () => {
  const { a, fetchFn } = make({ cooldownMs: 15 * MIN });
  a.notify(down({ at: T0 }));
  a.notify(back({ at: T0 + 3 * MIN, end: T0 + 3 * MIN }));
  // Down again after 8 minutes, inside the cooldown: held back, and it stays down.
  a.notify(down({ start: T0 + 8 * MIN, at: T0 + 8 * MIN }));
  await a.idle();
  assert.equal(fetchFn.calls.length, 2);
  const open = [[K, T0 + 8 * MIN]];
  // Rounds inside the cooldown send nothing, even with no repeat_minutes.
  a.remind(open, T0 + 10 * MIN);
  a.remind(open, T0 + 14 * MIN);
  await a.idle();
  assert.equal(fetchFn.calls.length, 2);
  // At 15 minutes after the last "down" alert the deferred alert goes out as a normal down alert, once.
  a.remind(open, T0 + 15 * MIN + 30_000);
  a.remind(open, T0 + 16 * MIN);
  await a.idle();
  assert.equal(fetchFn.calls.length, 3);
  const body = JSON.parse(fetchFn.calls[2].init.body);
  assert.equal(body.event, 'down');
  assert.equal(body.since, new Date(T0 + 8 * MIN).toISOString());
  // The recovery of that incident is then announced too.
  a.notify(back({ start: T0 + 8 * MIN, end: T0 + 30 * MIN, at: T0 + 31 * MIN }));
  await a.idle();
  assert.equal(fetchFn.calls.length, 4);
});

test('a held back down is not sent when the node has recovered, nor when down is not an event', async () => {
  const { a, fetchFn } = make({ cooldownMs: 15 * MIN });
  a.notify(down({ at: T0 }));
  a.notify(down({ at: T0 + 5 * MIN }));
  a.notify(back({ at: T0 + 6 * MIN, end: T0 + 6 * MIN }));
  a.remind([], T0 + 20 * MIN);
  await a.idle();
  assert.equal(fetchFn.calls.length, 1);
  const rec = make({ cooldownMs: 15 * MIN, events: ['recovered'] });
  rec.a.notify(down({ at: T0 }));
  rec.a.notify(back({ at: T0 + MIN }));
  rec.a.notify(down({ at: T0 + 5 * MIN }));
  rec.a.remind([[K, T0 + 5 * MIN]], T0 + 20 * MIN);
  await rec.a.idle();
  assert.equal(rec.fetchFn.calls.length, 1);
});

test('a queue that fills again inside the cooldown and stays full is announced after it', async () => {
  const { a, f } = queueAlerter({ queueSamples: 1, cooldownMs: 15 * MIN });
  const full = { full: true, queued: 9 };
  a.observeQueue(K, full, T0);
  a.observeQueue(K, { full: false }, T0 + 3 * MIN);
  a.observeQueue(K, full, T0 + 8 * MIN);
  await a.idle();
  assert.equal(f.calls.length, 2);
  for (const m of [10, 12, 14]) a.observeQueue(K, full, T0 + m * MIN);
  await a.idle();
  assert.equal(f.calls.length, 2);
  a.observeQueue(K, full, T0 + 15 * MIN);
  a.observeQueue(K, full, T0 + 16 * MIN);
  await a.idle();
  assert.equal(f.calls.length, 3);
  const body = JSON.parse(f.calls[2].init.body);
  assert.equal(body.event, 'announce_queue_full');
  assert.equal(body.since, new Date(T0 + 8 * MIN).toISOString());
  a.observeQueue(K, { full: false }, T0 + 20 * MIN);
  await a.idle();
  assert.equal(f.calls.length, 4);
  assert.equal(JSON.parse(f.calls[3].init.body).event, 'announce_queue_cleared');
});

test('the queue-cleared text counts from the first full sample', () => {
  const w = createQueueWatch(3);
  w.observe(K, 1, 1, T0);
  w.observe(K, 1, 1, T0 + 30_000);
  assert.equal(w.since(K), T0);
  w.observe(K, 1, 1, T0 + 60_000);
  assert.equal(w.since(K), T0);
  w.observe(K, 0, 1, T0 + 90_000);
  w.observe(K, 1, 1, T0 + 120_000);
  assert.equal(w.since(K), T0 + 120_000);
  assert.equal(w.since('nobody:1'), null);
});

test('an incident left open by uptime.json gets reminders after a restart, with the real alerter', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  let clock = T0;
  const first = new Monitor({ targets: [{ host: 'front.test', port: 4242 }], dataDir: dir, now: () => clock, probeFn: async () => ({ up: false, ms: 0, error: 'x' }) });
  await first.checkAll();
  clock += 30_000;
  await first.checkAll();
  assert.equal(first.uptime.openIncidents().length, 1);

  const fetchFn = fakeFetch();
  const alerts = new Alerter({ channels: [{ type: 'webhook', url: 'https://h.example/x', format: 'generic' }], repeatMs: 30 * MIN, now: () => clock, fetchFn, log: () => {} });
  const second = new Monitor({ targets: [{ host: 'front.test', port: 4242 }], dataDir: dir, now: () => clock, probeFn: async () => ({ up: false, ms: 0, error: 'x' }), alerts });
  await second.load();
  for (let i = 0; i < 3; i++) {
    clock += 30_000;
    await second.checkAll();
  }
  await alerts.idle();
  // The restart itself announces nothing, and the reminders count from the first round after it.
  assert.equal(fetchFn.calls.length, 0);
  clock += 31 * MIN;
  await second.checkAll();
  await alerts.idle();
  assert.equal(fetchFn.calls.length, 1);
  assert.equal(JSON.parse(fetchFn.calls[0].init.body).event, 'still_down');
  clock += 31 * MIN;
  await second.checkAll();
  await alerts.idle();
  assert.equal(fetchFn.calls.length, 2);
});

test('a channel that keeps failing does not hold up the others while it waits to retry', async () => {
  const fetchFn = async (url) => {
    if (url.includes('dead')) return new Response('', { status: 503 });
    return new Response('', { status: 200 });
  };
  const sent = [];
  const mailFn = async (_c, mail) => void sent.push(mail.subject);
  let wake;
  const never = new Promise((r) => (wake = r));
  const { a } = make({
    fetchFn,
    mailFn,
    cooldownMs: 0,
    // The retry wait of the dead webhook does not end until the test says so.
    sleep: () => never,
    channels: [
      { type: 'webhook', url: 'https://dead.example/x', format: 'generic' },
      { type: 'email', host: 'x.test', port: 1, security: 'tls', from: 'a@example.org', to: ['b@example.org'] },
    ],
  });
  for (let i = 0; i < 5; i++) a.notify(down({ key: `n${i}.test:1` }));
  // The mails all go out although both webhook slots would have been held for the whole wait.
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(sent.length, 5);
  let idled = false;
  a.idle().then(() => (idled = true));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(idled, false);
  a.stop();
  wake();
  await a.idle();
});

test('a retry that was waiting when the alerter stops is dropped', async () => {
  let wake;
  const gate = new Promise((r) => (wake = r));
  const { a, fetchFn } = make({ fetchFn: fakeFetch([500]), sleep: () => gate });
  a.notify(down());
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(fetchFn.calls.length, 1);
  a.stop();
  wake();
  await a.idle();
  assert.equal(fetchFn.calls.length, 1);
});
