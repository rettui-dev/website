// The signing client for the management listener of a rettui node (`rettui node
// --manage-listen`). Every request carries an HMAC over a canonical string and every answer
// is signed back, so a spoofed "ok" over a private network is caught. The secrets live only
// in the closure of createManageClient: no result, error or log line ever holds one.
import crypto from 'node:crypto';
import { readLimited } from './stats.js';
import { cleanText } from './propagation.js';

export const MANAGE_TIMEOUT_MS = 12_000;
// The node's answers are cut off here; a larger one is reported as too-large.
export const MANAGE_MAX_BYTES = 64 * 1024;
// The node refuses bodies over 16 KiB, so there is no point sending one.
export const MANAGE_MAX_REQUEST_BYTES = 16 * 1024;
export const ACTOR_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const SIGNATURE_RE = /^v1=([0-9a-f]{64})$/;
// What a signed question may look like: an absolute path with a query, printable ASCII, no fragment.
const TARGET_RE = /^\/[\x21-\x7e]*$/;
const MAX_TIME = 99_999_999_999; // 11 digits, like the node's timestamp header
const MAX_STRING = 4096;
const MAX_KEY = 64;
const MAX_ITEMS = 1000;
const MAX_DEPTH = 8;

const hmac = (secret, text) => crypto.createHmac('sha256', Buffer.from(secret, 'utf8')).update(text).digest('hex');
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

class Invalid extends Error {}

const usable = (secret) => typeof secret === 'string' && secret.length > 0;

// The headers that sign one request. body is the exact text (or bytes) that will be sent;
// a GET has none. ts (unix seconds) and nonce (32 lower case hex) default to fresh values.
// Throws Error on anything the node would refuse, naming the argument and never the secret.
export function signRequest({ secret, method, pathAndQuery, actor, body = '', ts = Math.floor(Date.now() / 1000), nonce = crypto.randomBytes(16).toString('hex') } = {}) {
  if (!usable(secret)) throw new Error('signRequest: the secret must be a non-empty string');
  if (typeof method !== 'string' || !/^[A-Z]+$/.test(method)) throw new Error('signRequest: the method must be upper case letters');
  if (typeof pathAndQuery !== 'string' || !TARGET_RE.test(pathAndQuery) || pathAndQuery.includes('#')) throw new Error('signRequest: pathAndQuery must be a path starting with / in printable ASCII, without a fragment');
  if (typeof actor !== 'string' || !ACTOR_RE.test(actor)) throw new Error('signRequest: the actor must be 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit');
  if (!Number.isInteger(ts) || ts < 0 || ts > MAX_TIME) throw new Error('signRequest: ts must be unix seconds');
  if (typeof nonce !== 'string' || !NONCE_RE.test(nonce)) throw new Error('signRequest: the nonce must be 32 lower case hex characters');
  if (typeof body !== 'string' && !(body instanceof Uint8Array)) throw new Error('signRequest: the body must be text or bytes');
  const canonical = `v1\n${ts}\n${nonce}\n${method}\n${pathAndQuery}\n${actor}\n${sha256(body)}`;
  return {
    'X-Rettui-Timestamp': String(ts),
    'X-Rettui-Nonce': nonce,
    'X-Rettui-Actor': actor,
    'X-Rettui-Signature': `v1=${hmac(secret, canonical)}`,
  };
}

// Whether an answer carries the node's signature for the request with this nonce. Never throws:
// anything odd is false. The comparison takes the same time wherever the values differ.
export function verifyResponse(args) {
  try {
    const { secret, nonce, status, bodyText, header } = args ?? {};
    if (!usable(secret) || typeof nonce !== 'string' || !Number.isInteger(status) || typeof bodyText !== 'string' || typeof header !== 'string') return false;
    const m = SIGNATURE_RE.exec(header);
    if (!m) return false;
    const expected = hmac(secret, `v1-response\n${nonce}\n${status}\n${sha256(bodyText)}`);
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(m[1], 'hex'));
  } catch {
    return false;
  }
}

// The node's JSON with every string cleaned (no control, direction or zero-width characters),
// and size, depth and key names bounded. Throws Invalid on what cannot be kept.
function clean(v, depth = 0) {
  if (depth > MAX_DEPTH) throw new Invalid('too deep');
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Invalid('not a number');
    return v;
  }
  if (typeof v === 'string') return cleanText(v, MAX_STRING) ?? '';
  if (Array.isArray(v)) {
    if (v.length > MAX_ITEMS) throw new Invalid('too many items');
    return v.map((x) => clean(x, depth + 1));
  }
  if (typeof v === 'object') {
    const keys = Object.keys(v);
    if (keys.length > MAX_ITEMS) throw new Invalid('too many keys');
    const out = {};
    for (const k of keys) {
      const name = cleanText(k, MAX_KEY);
      // A key that cleans to __proto__ would change the object's prototype instead of adding a key.
      if (!name || name === '__proto__') continue;
      out[name] = clean(v[k], depth + 1);
    }
    return out;
  }
  throw new Invalid('unexpected value');
}

const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const validTime = (v) => Number.isInteger(v) && v >= 0 && v <= MAX_TIME;

const fail = (error, more = {}) => ({ ok: false, error, ...more });

// The client for the nodes of the config (loadConfig(...).manage: host key to {url, secret,
// confirmSeconds}). The secrets are copied into this closure and nothing returns them.
// call() always resolves, to one of
//   {ok: true, status, body, skewSeconds?}  a signed answer; body is the cleaned JSON object
//                                           (node errors such as 409 are answers too)
//   {ok: false, error}  unknown-node | timeout | network | too-large | invalid | unsigned
//                       | clock (with nodeTime and skewSeconds: node_time minus our time)
// error is a short code and never text from the node or the request.
export function createManageClient({ nodes, fetchFn = fetch, now = Date.now, timeoutMs = MANAGE_TIMEOUT_MS } = {}) {
  const known = new Map();
  if (nodes instanceof Map) {
    for (const [host, n] of nodes) {
      if (typeof host === 'string' && isMap(n) && typeof n.url === 'string' && usable(n.secret)) {
        known.set(host, { base: n.url.replace(/\/+$/, ''), secret: n.secret, confirmSeconds: Number.isInteger(n.confirmSeconds) ? n.confirmSeconds : 300 });
      }
    }
  }

  async function call(host, method, pathAndQuery, actor, bodyObj) {
    try {
      const node = typeof host === 'string' ? known.get(host) : undefined;
      if (!node) return fail('unknown-node');
      if ((method !== 'GET' && method !== 'POST') || typeof actor !== 'string' || !ACTOR_RE.test(actor)) return fail('invalid');
      if (typeof pathAndQuery !== 'string' || !TARGET_RE.test(pathAndQuery) || pathAndQuery.includes('#')) return fail('invalid');
      // The signed path must be exactly what the node receives: refuse one the URL parser would rewrite.
      const target = new URL(node.base + pathAndQuery);
      if (target.pathname + target.search !== pathAndQuery) return fail('invalid');
      let body = '';
      if (method === 'POST') body = JSON.stringify(bodyObj === undefined ? {} : bodyObj) ?? '';
      if (method === 'GET' && bodyObj !== undefined) return fail('invalid');
      if (Buffer.byteLength(body) > MANAGE_MAX_REQUEST_BYTES) return fail('invalid');

      const nonce = crypto.randomBytes(16).toString('hex');
      const sent = Math.floor(now() / 1000);
      const headers = { Accept: 'application/json', ...signRequest({ secret: node.secret, method, pathAndQuery, actor, body, ts: sent, nonce }) };
      if (method === 'POST') headers['Content-Type'] = 'application/json';

      let res;
      let text;
      try {
        res = await fetchFn(target.href, { method, headers, ...(method === 'POST' ? { body } : {}), redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
        text = await readLimited(res, MANAGE_MAX_BYTES);
      } catch (err) {
        return fail(err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'timeout' : 'network');
      }
      if (text === null) return fail('too-large');
      const status = res.status;
      if (!Number.isInteger(status) || status < 200 || status > 599) return fail('invalid');
      // Every answer after the node has accepted our signature is signed; the rest is not trusted.
      if (!verifyResponse({ secret: node.secret, nonce, status, bodyText: text, header: res.headers.get('x-rettui-signature') ?? undefined })) return fail('unsigned');

      let parsed;
      try {
        parsed = clean(JSON.parse(text));
      } catch {
        return fail('invalid');
      }
      if (!isMap(parsed)) return fail('invalid');

      const hasTime = Object.hasOwn(parsed, 'node_time');
      if (hasTime && !validTime(parsed.node_time)) return fail('invalid');
      const skewSeconds = hasTime ? Math.round(parsed.node_time - now() / 1000) : undefined;
      if (status === 401 && parsed.error === 'clock_skew') {
        if (!hasTime) return fail('invalid');
        return fail('clock', { nodeTime: parsed.node_time, skewSeconds });
      }
      if (status >= 300 && status < 400) return fail('invalid');
      return { ok: true, status, body: parsed, ...(skewSeconds === undefined ? {} : { skewSeconds }) };
    } catch {
      return fail('network');
    }
  }

  return Object.freeze({
    call,
    has: (host) => typeof host === 'string' && known.has(host),
    confirmSeconds: (host) => (typeof host === 'string' ? (known.get(host)?.confirmSeconds ?? null) : null),
  });
}

// Clears the secrets from the nodes of the config once a client has copied them, so the client
// is the only thing that holds them and a dump of the config shows none.
export function forgetManageSecrets(nodes) {
  if (!(nodes instanceof Map)) return;
  for (const n of nodes.values()) if (isMap(n) && Object.hasOwn(n, 'secret')) n.secret = null;
}
