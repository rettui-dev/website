import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import util from 'node:util';
import { loadConfigFile } from '../lib/config.js';
import { createManageClient, forgetManageSecrets, signRequest, verifyResponse } from '../lib/manage.js';
import { startManageNode } from './helpers/manage-node.js';

// The vector from the design, shared with the node's tests.
const SECRET = 'rettui-manage-test-secret-0123456789abcdef';
const NONCE = '00112233445566778899aabbccddeeff';
const BODY = '{"revision":"00000000000000000000000000000000","changes":{"pn_name":"Hilltop"}}';
const REQUEST_SIGNATURE = 'v1=e67c8c58195470e27718090f17e8615c1197e216a7c714ef6e9228aa84fccce7';
const RESPONSE_SIGNATURE = 'v1=1f2f4a3b7b5ceaea194df98320fcf931e548b9fc21387d02aad45a11aa990ef2';
const HOST = 'node.test:4242';

const vectorArgs = { secret: SECRET, method: 'POST', pathAndQuery: '/manage/v1/settings', actor: 'alice', body: BODY, ts: 1763640000, nonce: NONCE };

test('the request signature matches the design vector', () => {
  const h = signRequest(vectorArgs);
  assert.deepEqual(h, {
    'X-Rettui-Timestamp': '1763640000',
    'X-Rettui-Nonce': NONCE,
    'X-Rettui-Actor': 'alice',
    'X-Rettui-Signature': REQUEST_SIGNATURE,
  });
  // Bytes sign the same as the text.
  assert.equal(signRequest({ ...vectorArgs, body: Buffer.from(BODY) })['X-Rettui-Signature'], REQUEST_SIGNATURE);
});

test('every part of the request is covered by the signature', () => {
  const sig = (over) => signRequest({ ...vectorArgs, ...over })['X-Rettui-Signature'];
  for (const over of [{ secret: `${SECRET}x` }, { method: 'GET' }, { pathAndQuery: '/manage/v1/settings?a=1' }, { actor: 'bob' }, { body: `${BODY} ` }, { ts: 1763640001 }, { nonce: 'f'.repeat(32) }]) {
    assert.notEqual(sig(over), REQUEST_SIGNATURE, JSON.stringify(over).replace(SECRET, '..'));
  }
  // A GET signs the hash of the empty text.
  assert.equal(sig({ method: 'GET', body: undefined }), sig({ method: 'GET', body: '' }));
});

test('signRequest refuses what the node would refuse, without naming the secret', () => {
  for (const over of [{ secret: '' }, { secret: undefined }, { method: 'post' }, { pathAndQuery: 'manage' }, { pathAndQuery: '/a b' }, { pathAndQuery: '/a#b' }, { pathAndQuery: '/é' }, { actor: '' }, { actor: '-alice' }, { actor: 'a'.repeat(33) }, { actor: 'a\nb' }, { ts: 1.5 }, { ts: -1 }, { ts: 1e12 }, { ts: '1763640000' }, { nonce: NONCE.toUpperCase() }, { nonce: 'abc' }, { body: 5 }]) {
    assert.throws(() => signRequest({ ...vectorArgs, ...over }), (e) => e instanceof Error && !e.message.includes(SECRET), JSON.stringify(over));
  }
  assert.throws(() => signRequest(), Error);
  // Without ts and nonce it makes fresh ones.
  const a = signRequest({ secret: SECRET, method: 'GET', pathAndQuery: '/manage/v1/state', actor: 'alice' });
  const b = signRequest({ secret: SECRET, method: 'GET', pathAndQuery: '/manage/v1/state', actor: 'alice' });
  assert.match(a['X-Rettui-Nonce'], /^[0-9a-f]{32}$/);
  assert.notEqual(a['X-Rettui-Nonce'], b['X-Rettui-Nonce']);
  assert.match(a['X-Rettui-Timestamp'], /^\d{10}$/);
});

test('the response signature matches the design vector and rejects everything else', () => {
  const good = { secret: SECRET, nonce: NONCE, status: 200, bodyText: '{"id":"x"}', header: RESPONSE_SIGNATURE };
  assert.equal(verifyResponse(good), true);
  for (const over of [{ secret: 'other-secret-0123456789abcdef0123456789' }, { nonce: 'f'.repeat(32) }, { status: 201 }, { bodyText: '{"id":"y"}' }, { header: RESPONSE_SIGNATURE.replace('v1=', 'v2=') }, { header: RESPONSE_SIGNATURE.toUpperCase() }, { header: RESPONSE_SIGNATURE.slice(0, -1) }, { header: `${RESPONSE_SIGNATURE}0` }, { header: ` ${RESPONSE_SIGNATURE}` }, { header: RESPONSE_SIGNATURE.slice(3) }, { header: '' }, { header: undefined }, { header: null }, { header: 5 }, { status: '200' }, { status: 200.5 }, { bodyText: undefined }, { bodyText: Buffer.from('{"id":"x"}') }, { nonce: undefined }, { secret: '' }, { secret: undefined }]) {
    assert.equal(verifyResponse({ ...good, ...over }), false, JSON.stringify(over));
  }
  assert.equal(verifyResponse(), false);
  assert.equal(verifyResponse(null), false);
});

// ---- the client against a stub node ----

async function setup(opts = {}) {
  const node = await startManageNode({ secret: SECRET, ...opts.node });
  const nodes = new Map([[HOST, { url: node.url, secret: SECRET, confirmSeconds: 120 }]]);
  const client = createManageClient({ nodes, timeoutMs: 2000, ...opts.client });
  return { node, client, nodes, close: () => node.close() };
}

test('a GET and a POST are signed the way the node checks them, and the answers verify', async () => {
  const s = await setup();
  try {
    const state = await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice');
    assert.equal(state.ok, true);
    assert.equal(state.status, 200);
    assert.equal(state.body.v, 1);
    assert.equal(state.body.settings.length, 4);
    assert.equal(typeof state.skewSeconds, 'number');
    assert.ok(Math.abs(state.skewSeconds) <= 1);

    const set = await s.client.call(HOST, 'POST', '/manage/v1/settings', 'alice', { revision: state.body.settings_revision, changes: { pn_name: 'Valley' } });
    assert.equal(set.ok, true);
    assert.equal(set.status, 200);
    assert.deepEqual(set.body.applied, [{ key: 'pn_name', from: 'Hilltop', to: 'Valley' }]);

    // Same revision again: the node answers 409, which is a signed answer, not a failure.
    const stale = await s.client.call(HOST, 'POST', '/manage/v1/settings', 'alice', { revision: state.body.settings_revision, changes: { pn_name: 'Other' } });
    assert.equal(stale.ok, true);
    assert.equal(stale.status, 409);
    assert.equal(stale.body.error, 'stale_revision');

    const restart = await s.client.call(HOST, 'POST', '/manage/v1/restart', 'bob', {});
    assert.deepEqual([restart.ok, restart.status, restart.body.state], [true, 202, 'restarting']);
    const again = await s.client.call(HOST, 'POST', '/manage/v1/restart', 'bob');
    assert.deepEqual([again.ok, again.status, again.body.error], [true, 409, 'restarting']);

    const back = await s.client.call(HOST, 'POST', '/manage/v1/rollback', 'alice', { id: set.body.id });
    assert.deepEqual([back.ok, back.status, back.body.applied], [true, 200, [{ key: 'pn_name', from: 'Valley', to: 'Hilltop' }]]);
    const missing = await s.client.call(HOST, 'POST', '/manage/v1/rollback', 'alice', { id: '0'.repeat(16) });
    assert.deepEqual([missing.status, missing.body.error], [404, 'unknown_change']);

    const audit = await s.client.call(HOST, 'GET', '/manage/v1/audit?limit=2', 'alice');
    assert.equal(audit.body.entries.length, 2);
    assert.equal(audit.body.more, true);
    const older = await s.client.call(HOST, 'GET', `/manage/v1/audit?before=${audit.body.entries[1].seq}&limit=5`, 'alice');
    assert.equal(older.body.entries.length, 1);

    // The node verified every request, and saw the actor and the exact path with its query.
    assert.ok(s.node.requests.length >= 9);
    assert.ok(s.node.requests.every((r) => r.signed));
    assert.deepEqual(s.node.requests.map((r) => r.actor).slice(0, 2), ['alice', 'alice']);
    assert.ok(s.node.requests.some((r) => r.path === '/manage/v1/audit?limit=2'));
    // A POST without a body sends {}.
    assert.equal(s.node.requests.find((r) => r.actor === 'bob' && r.method === 'POST').body, '{}');
  } finally {
    await s.close();
  }
});

test('the stub node refuses a wrong secret, and the client reports the unsigned answer', async () => {
  const s = await setup();
  try {
    const nodes = new Map([[HOST, { url: s.node.url, secret: 'y'.repeat(40) }]]);
    const r = await createManageClient({ nodes, timeoutMs: 2000 }).call(HOST, 'GET', '/manage/v1/state', 'alice');
    assert.deepEqual(r, { ok: false, error: 'unsigned' });
    assert.equal(s.node.requests.at(-1).signed, false);
  } finally {
    await s.close();
  }
});

test('an unknown node, bad input and a bad path are refused without a request', async () => {
  const s = await setup();
  try {
    const bad = async (...args) => assert.deepEqual(await s.client.call(...args), { ok: false, error: args[0] === 'other:1' || args[0] === '__proto__' ? 'unknown-node' : 'invalid' }, JSON.stringify(args));
    await bad('other:1', 'GET', '/manage/v1/state', 'alice');
    await bad('__proto__', 'GET', '/manage/v1/state', 'alice');
    await bad(HOST, 'PUT', '/manage/v1/state', 'alice');
    await bad(HOST, 'GET', '/manage/v1/state', 'not an actor');
    await bad(HOST, 'GET', '/manage/v1/state', undefined);
    await bad(HOST, 'GET', 'manage/v1/state', 'alice');
    await bad(HOST, 'GET', '/manage/v1/../v1/state', 'alice'); // the URL parser would rewrite it
    await bad(HOST, 'GET', '/manage/v1/state#x', 'alice');
    await bad(HOST, 'GET', '/manage/v1/state?', 'alice');
    await bad(HOST, 'GET', '/manage/v1/state', 'alice', {});
    await bad(HOST, 'POST', '/manage/v1/settings', 'alice', { big: 'x'.repeat(16 * 1024) });
    assert.deepEqual(await s.client.call(undefined, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'unknown-node' });
    assert.equal(s.node.requests.length, 0);
  } finally {
    await s.close();
  }
});

test('a node that signs with another secret, or not at all, is reported as unsigned', async () => {
  const s = await setup();
  try {
    for (const mode of ['wrong-signature', 'unsigned']) {
      s.node.misbehave = mode;
      assert.deepEqual(await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'unsigned' }, mode);
    }
  } finally {
    await s.close();
  }
});

test('a node whose clock is off gets error clock, with its time and the skew', async () => {
  const s = await setup();
  try {
    s.node.misbehave = 'clock_skew';
    const r = await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice');
    assert.equal(r.ok, false);
    assert.equal(r.error, 'clock');
    assert.ok(Math.abs(r.skewSeconds - 3600) <= 1);
    assert.ok(Math.abs(r.nodeTime - Math.floor(Date.now() / 1000) - 3600) <= 1);
  } finally {
    await s.close();
  }
});

test('skewSeconds is node_time minus our clock, and our own clock is what signs', async () => {
  // The client's clock is an hour behind: the node sees a timestamp 3600 s old and says so, signed.
  const ahead = Date.now() - 3600 * 1000;
  const s = await setup({ client: { now: () => ahead } });
  try {
    const r = await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice');
    assert.equal(r.error, 'clock');
    assert.ok(Math.abs(r.skewSeconds - 3600) <= 1);
  } finally {
    await s.close();
  }
});

test('a node that is too slow is a timeout', async () => {
  const s = await setup({ node: { slowMs: 2000 }, client: { timeoutMs: 150 } });
  try {
    s.node.misbehave = 'slow';
    assert.deepEqual(await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'timeout' });
  } finally {
    await s.close();
  }
});

test('an answer over 64 KiB is too-large', async () => {
  const s = await setup();
  try {
    s.node.misbehave = 'oversize';
    assert.deepEqual(await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'too-large' });
  } finally {
    await s.close();
  }
});

test('a redirect is never followed', async () => {
  const s = await setup();
  try {
    s.node.misbehave = 'redirect';
    const r = await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice');
    assert.deepEqual(r, { ok: false, error: 'network' });
    assert.equal(s.node.requests.length, 1);
  } finally {
    await s.close();
  }
  // Even from a fetch that returns the redirect instead of throwing.
  const fetchFn = async () => new Response('', { status: 302, headers: { Location: 'http://127.0.0.1:1/' } });
  const c = createManageClient({ nodes: new Map([[HOST, { url: 'http://127.0.0.1:1', secret: SECRET }]]), fetchFn });
  assert.equal((await c.call(HOST, 'GET', '/manage/v1/state', 'alice')).ok, false);
});

test('fetch is called with redirect error, the signed target and a timeout signal', async () => {
  let seen;
  const fetchFn = async (url, init) => {
    seen = { url, init };
    throw new TypeError('connect ECONNREFUSED');
  };
  const c = createManageClient({ nodes: new Map([[HOST, { url: 'http://10.0.0.2:8750', secret: SECRET }]]), fetchFn });
  assert.deepEqual(await c.call(HOST, 'POST', '/manage/v1/restart?x=1', 'alice', {}), { ok: false, error: 'network' });
  assert.equal(seen.url, 'http://10.0.0.2:8750/manage/v1/restart?x=1');
  assert.equal(seen.init.redirect, 'error');
  assert.equal(seen.init.method, 'POST');
  assert.ok(seen.init.signal instanceof AbortSignal);
  assert.equal(seen.init.headers['Content-Type'], 'application/json');
  assert.match(seen.init.headers['X-Rettui-Signature'], /^v1=[0-9a-f]{64}$/);
});

test('answers that are signed but not usable are invalid', async () => {
  const s = await setup();
  try {
    for (const mode of ['bad-json', 'array', 'bad-node-time']) {
      s.node.misbehave = mode;
      assert.deepEqual(await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'invalid' }, mode);
    }
  } finally {
    await s.close();
  }
});

test('text from the node is cleaned and a __proto__ key does not change the prototype', async () => {
  const s = await setup();
  try {
    s.node.misbehave = 'control-chars';
    const r = await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice');
    assert.equal(r.ok, true);
    assert.equal(r.body.version, '2.5.0');
    assert.equal(r.body.k, 'ab');
    assert.deepEqual(r.body.nested, { list: ['x'] });
    assert.equal(Object.getPrototypeOf(r.body), Object.prototype);
    assert.equal(Object.hasOwn(r.body, '__proto__'), false);
    assert.equal(r.body.x, undefined);
  } finally {
    await s.close();
  }
});

// A fetch that returns a ready answer, signed with the secret for whatever nonce it was sent.
function signedFetch(status, text, { secret = SECRET, headers = {} } = {}) {
  return async (url, init) => {
    const nonce = init.headers['X-Rettui-Nonce'];
    const sig = crypto.createHmac('sha256', secret).update(`v1-response\n${nonce}\n${status}\n${crypto.createHash('sha256').update(text).digest('hex')}`).digest('hex');
    return new Response(text, { status, headers: { 'X-Rettui-Signature': `v1=${sig}`, ...headers } });
  };
}
const withFetch = (fetchFn, now) => createManageClient({ nodes: new Map([[HOST, { url: 'http://10.0.0.2:8750/', secret: SECRET }]]), fetchFn, ...(now ? { now } : {}) });

test('odd but signed answers never throw', async () => {
  const call = (status, text) => withFetch(signedFetch(status, text)).call(HOST, 'GET', '/manage/v1/state', 'alice');
  assert.deepEqual(await call(200, ''), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(200, 'null'), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(200, '"text"'), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(200, '5'), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(200, '{"a":' + '['.repeat(50) + ']'.repeat(50) + '}'), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(200, `{"a":[${'0,'.repeat(1500)}0]}`), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(401, '{"error":"clock_skew","message":"x"}'), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(401, '{"error":"clock_skew","node_time":-5}'), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(401, '{"error":"clock_skew","node_time":1.5}'), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(401, '{"error":"clock_skew","node_time":1e30}'), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(200, '{"node_time":null}'), { ok: false, error: 'invalid' });
  assert.deepEqual(await call(302, '{}'), { ok: false, error: 'invalid' });
  // A 401 that is not clock_skew is a plain answer; one with no node_time has no skew.
  assert.deepEqual(await call(429, '{"error":"rate_limited","retry_after":30}'), { ok: true, status: 429, body: { error: 'rate_limited', retry_after: 30 } });
  assert.deepEqual(await call(401, '{"error":"unauthorised"}'), { ok: true, status: 401, body: { error: 'unauthorised' } });
  // A signature made for another status, or for a different body, does not carry over.
  const swapped = async (url, init) => {
    const r = await signedFetch(200, '{"ok":true}')(url, init);
    return new Response('{"ok":false}', { status: 200, headers: r.headers });
  };
  assert.deepEqual(await withFetch(swapped).call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'unsigned' });
  // A fetch that throws something odd, or a response without headers, is a network failure.
  assert.deepEqual(await withFetch(async () => { throw 'text'; }).call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'network' });
  assert.deepEqual(await withFetch(async () => ({})).call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'network' });
  assert.deepEqual(await withFetch(async () => null).call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'network' });
  const timeout = Object.assign(new Error('x'), { name: 'TimeoutError' });
  assert.deepEqual(await withFetch(async () => { throw timeout; }).call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'timeout' });
});

test('skewSeconds is rounded and uses the injected clock', async () => {
  const at = 1_763_640_000_400; // 400 ms past the second
  const c = withFetch(signedFetch(200, '{"node_time":1763640030}'), () => at);
  assert.deepEqual(await c.call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: true, status: 200, body: { node_time: 1763640030 }, skewSeconds: 30 });
});

test('the content-length of an answer over the limit is refused without reading it', async () => {
  const fetchFn = async () => new Response('{}', { status: 200, headers: { 'Content-Length': String(64 * 1024 + 1) } });
  assert.deepEqual(await withFetch(fetchFn).call(HOST, 'GET', '/manage/v1/state', 'alice'), { ok: false, error: 'too-large' });
});

test('the client only keeps usable nodes, and offers has and confirmSeconds, never the secret', () => {
  const nodes = new Map([
    ['a:1', { url: 'http://10.0.0.1:8750', secret: SECRET, confirmSeconds: 120 }],
    ['b:1', { url: 'http://10.0.0.2:8750', secret: SECRET }],
    ['c:1', { url: 'http://10.0.0.3:8750', secret: null }],
    ['d:1', null],
  ]);
  const c = createManageClient({ nodes });
  assert.deepEqual([c.has('a:1'), c.has('b:1'), c.has('c:1'), c.has('d:1'), c.has('x'), c.has(undefined)], [true, true, false, false, false, false]);
  assert.deepEqual([c.confirmSeconds('a:1'), c.confirmSeconds('b:1'), c.confirmSeconds('c:1'), c.confirmSeconds(5)], [120, 300, null, null]);
  assert.deepEqual(Object.keys(c).sort(), ['call', 'confirmSeconds', 'has']);
  assert.equal(JSON.stringify(c), '{}');
  assert.equal(Object.isFrozen(c), true);
  assert.equal(createManageClient().has('a:1'), false);
  assert.equal(createManageClient({ nodes: { 'a:1': { url: 'http://x', secret: SECRET } } }).has('a:1'), false);
});

test('the secret is in no result, error or log line', async () => {
  const lines = [];
  const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  for (const k of Object.keys(orig)) console[k] = (...a) => lines.push(a.map(String).join(' '));
  const s = await setup();
  const results = [];
  try {
    results.push(await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice'));
    results.push(await s.client.call(HOST, 'POST', '/manage/v1/settings', 'alice', { revision: 'x', changes: {} }));
    results.push(await s.client.call('other:1', 'GET', '/manage/v1/state', 'alice'));
    for (const mode of ['wrong-signature', 'unsigned', 'clock_skew', 'oversize', 'redirect', 'bad-json']) {
      s.node.misbehave = mode;
      results.push(await s.client.call(HOST, 'GET', '/manage/v1/state', 'alice'));
    }
    // Errors from the fetch that mention the request (headers and all) are not passed on.
    const leaky = async (url, init) => { throw new TypeError(`failed ${url} ${JSON.stringify(init.headers)} ${SECRET}`); };
    results.push(await withFetch(leaky).call(HOST, 'GET', '/manage/v1/state', 'alice'));
    // A node that echoes the secret back has it cleaned only as text; the client adds nothing of its own.
    results.push(await s.client.call(HOST, 'GET', '/manage/v1/state', 'bad actor'));
  } finally {
    Object.assign(console, orig);
    await s.close();
  }
  assert.ok(results.length >= 10);
  const text = JSON.stringify(results);
  assert.equal(text.includes(SECRET), false);
  assert.equal(text.includes('ECONNREFUSED'), false);
  assert.equal(lines.some((l) => l.includes(SECRET)), false);
  assert.throws(() => signRequest({ secret: SECRET, method: 'GET', pathAndQuery: 'bad', actor: 'alice' }), (e) => !e.message.includes(SECRET) && !String(e.stack).includes(SECRET));
});

test('once the client has the secrets, the config holds none of them, and the client still signs', async () => {
  const node = await startManageNode({ secret: SECRET });
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-manage-forget-'));
  try {
    await fs.writeFile(path.join(dir, 'a.secret'), `${SECRET}\n`, { mode: 0o600 });
    await fs.writeFile(path.join(dir, 'config.yaml'), `nodes:\n  - address: ${HOST}\n    manage_url: ${node.url}\n    manage_secret_file: a.secret\n`);
    const config = await loadConfigFile(path.join(dir, 'config.yaml'));
    assert.equal(config.manage.get(HOST).secret, SECRET);
    const client = createManageClient({ nodes: config.manage, timeoutMs: 2000 });
    forgetManageSecrets(config.manage);
    assert.equal(config.manage.get(HOST).secret, null);
    // Neither a full inspection nor JSON (Maps written out) shows the secret anywhere.
    const json = JSON.stringify(config, (_k, v) => (v instanceof Map ? [...v] : v instanceof Set ? [...v] : v));
    assert.equal(json.includes(SECRET), false);
    assert.equal(util.inspect(config, { depth: Infinity, showHidden: true }).includes(SECRET), false);
    const state = await client.call(HOST, 'GET', '/manage/v1/state', 'alice');
    assert.equal(state.ok, true);
    assert.equal(state.status, 200);
  } finally {
    await node.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('forgetManageSecrets ignores what is not a map of nodes', () => {
  for (const v of [undefined, null, 'x', [], {}]) assert.doesNotThrow(() => forgetManageSecrets(v));
  const nodes = new Map([['a', { url: 'http://10.0.0.2:1', secret: SECRET }], ['b', null], ['c', { url: 'http://10.0.0.3:1' }]]);
  forgetManageSecrets(nodes);
  assert.deepEqual([...nodes], [['a', { url: 'http://10.0.0.2:1', secret: null }], ['b', null], ['c', { url: 'http://10.0.0.3:1' }]]);
});
