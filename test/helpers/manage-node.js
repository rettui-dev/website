// A stub of a rettui node's management listener, on node:http, for tests. It checks every
// request with its own copy of the signing algorithm (not lib/manage.js, so the two are
// compared), keeps a small settings store and answers state, settings, restart, rollback, audit,
// reticulum and confirm with signed answers. A Reticulum change is pending until a test moves it on:
//   node.advance('probation' | 'rolling_back')  the node's own steps after a change
//   node.finish(outcome, message)               ends it: committed, rolled_back, rollback_failed, left
// node.pending and node.reticulumResult are what /state says, and a test may set them to anything.
// node.onConfirm(req), when set, runs before /confirm is answered (it may change the pending state).
// Set node.misbehave to make it break the protocol:
//   'wrong-signature'  signs answers with another secret
//   'unsigned'         no signature header at all
//   'clock_skew'       401 clock_skew (signed) with a node_time an hour ahead
//   'slow'             waits slowMs before answering
//   'oversize'         a signed 200 answer of 70 KiB
//   'redirect'         302 to the state URL
//   'bad-json'         a signed answer that is not JSON
//   'array'            a signed JSON array
//   'bad-node-time'    a signed state whose node_time is text
//   'control-chars'    a signed state with control and direction characters in its text
import crypto from 'node:crypto';
import http from 'node:http';

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
const hmac = (secret, text) => crypto.createHmac('sha256', secret).update(text).digest('hex');
const HEADER_RE = { ts: /^\d{1,11}$/, nonce: /^[0-9a-f]{32}$/, actor: /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/, sig: /^v1=[0-9a-f]{64}$/ };

export const FIELDS = [
  { key: 'display_name', label: 'Display name', help: 'The name other people see.', kind: 'text', access: 'change' },
  { key: 'pn_name', label: 'Propagation node name', help: 'Shown in lists.', kind: 'text', access: 'change' },
  { key: 'log_level', label: 'Log level', help: 'How much is logged.', kind: 'choice', choices: ['error', 'warn', 'info', 'debug'], access: 'change' },
  { key: 'pn_enabled', label: 'Propagation node', help: 'Turn off only.', kind: 'toggle', access: 'turn_off_only' },
];

// A sample of the node's Reticulum config, as the node's /state gives it: masked keys have no value.
// It holds hostile text (markup, control and direction characters, an over-long value) and more
// sections and keys than the website keeps (64 of each), for the tests of how it is cleaned.
export function sampleReticulum() {
  const sections = [
    { path: ['reticulum'], keys: [{ key: 'enable_transport', value: 'yes', set: true }, { key: 'share_instance', value: 'no', set: true }, { key: 'shared_instance_port', value: null, set: false }] },
    { path: ['interfaces', 'Hilltop TCP'], keys: [{ key: 'type', value: 'TCPClientInterface', set: true }, { key: 'target_host', value: 'hill.example.org', set: true }, { key: 'passphrase', value: 'hunter2', set: true }, { key: 'enabled', value: 'yes', set: true }] },
    { path: ['interfaces', '<img src=x onerror=alert(1)>\u202e\u0000'], keys: [{ key: '<b>type</b>\u200b', value: '<script>alert(1)</script>\u0007\n', set: true }, { key: 'long', value: 'v'.repeat(600), set: true }] },
    { path: ['interfaces', 'Big'], keys: Array.from({ length: 100 }, (_, i) => ({ key: `key_${i}`, value: String(i), set: true })) },
  ];
  for (let i = 0; i < 140; i++) sections.push({ path: ['interfaces', `Extra ${i}`], keys: [{ key: 'type', value: 'AutoInterface', set: true }] });
  // The hostile section is listed as editable too, and one that does not exist: the website keeps neither.
  const editable = [['reticulum'], ['interfaces', 'Hilltop TCP'], ['interfaces', '<img src=x onerror=alert(1)>\u202e\u0000'], ['interfaces', 'Nowhere']];
  return { revision: 'f'.repeat(32), shared_instance: false, truncated: false, sections, editable };
}

// A small Reticulum config the website may change: the [reticulum] section and two interfaces,
// one of them a pipe (never editable).
export function editableReticulum() {
  return {
    revision: 'e'.repeat(32),
    shared_instance: false,
    truncated: false,
    sections: [
      { path: ['reticulum'], keys: [{ key: 'enable_transport', value: 'no', set: true }, { key: 'share_instance', value: 'no', set: true }] },
      { path: ['interfaces', 'Hilltop TCP'], keys: [{ key: 'type', value: 'TCPServerInterface', set: true }, { key: 'interface_enabled', value: 'Yes', set: true }, { key: 'mode', value: 'full', set: true }, { key: 'listen_port', value: '4242', set: true }, { key: 'passphrase', value: null, set: true }] },
      { path: ['interfaces', 'Pipe'], keys: [{ key: 'type', value: 'PipeInterface', set: true }, { key: 'enabled', value: 'yes', set: true }] },
    ],
    editable: [['reticulum'], ['interfaces', 'Hilltop TCP']],
  };
}

// What the node allows the website to change, by section: the key, its aliases, and the rule.
const SWITCH = (v) => v === 'yes' || v === 'no';
const RET_KEYS = {
  reticulum: { enable_transport: { names: ['enable_transport'], ok: SWITCH } },
  interfaces: {
    enabled: { names: ['enabled', 'interface_enabled'], ok: SWITCH },
    mode: { names: ['mode', 'interface_mode'], ok: (v) => ['full', 'gateway', 'access_point', 'roaming', 'boundary'].includes(v) },
    announce_cap: { names: ['announce_cap'], ok: (v) => /^(0|[1-9][0-9]?|100)(\.[0-9]{1,2})?$/.test(v) && Number(v) > 0 && Number(v) <= 100 },
    bitrate: { names: ['bitrate'], ok: (v) => /^[1-9][0-9]{0,10}$/.test(v) && Number(v) >= 5 && Number(v) <= 10_000_000_000 },
    ingress_control: { names: ['ingress_control'], ok: SWITCH },
  },
};
const truthy = (v) => ['yes', 'true', 'on', '1'].includes(String(v).toLowerCase());

export async function startManageNode({ secret, now = Date.now, slowMs = 3000, misbehave = null, version = '2.5.0' } = {}) {
  const node = {
    misbehave,
    requests: [], // what arrived: {method, path, actor, body, signed}
    settings: { display_name: 'Stub', pn_name: 'Hilltop', log_level: 'info', pn_enabled: 'true' },
    audit: [],
    restart: null,
    seen: new Set(),
    seq: 0,
    reticulum: sampleReticulum(), // set to null or something else to change what /state says
    pending: null,
    reticulumResult: null,
    reticulumBefore: null, // the config before the pending change, put back by finish('rolled_back')
    onConfirm: null,
    reticulumEnableAllowed: false, // without it, a yes for enabled or enable_transport is not_allowed
  };
  const time = () => Math.floor(now() / 1000);
  const revision = () => sha256(FIELDS.map((f) => `${f.key}=${node.settings[f.key]}`).join('\n') + '\n').slice(0, 32);
  const newId = () => crypto.randomBytes(8).toString('hex');
  const log = (op, actor, changes, id, result = 'ok') => {
    node.audit.push({ seq: ++node.seq, time: time(), id, actor, op, changes, result, error: null });
  };
  const known = (key) => FIELDS.find((f) => f.key === key);

  // [status, object] for a request that passed the checks.
  function answer(method, path, actor, body) {
    const url = new URL(path, 'http://stub');
    const route = `${method} ${url.pathname}`;
    const err = (status, error, message, more = {}) => [status, { error, message, ...more }];
    if (route === 'GET /manage/v1/state') {
      return [200, {
        v: 1, node_time: time(), version, settings_revision: revision(),
        settings: FIELDS.map((f) => ({ ...f, value: node.settings[f.key] })),
        network: { state: 'running', shared_instance: false, interfaces_total: 2, interfaces_online: 2 },
        restart: node.restart, restart_allowed_at: null, pending: node.pending, reticulum_result: node.reticulumResult, reticulum_enable_allowed: node.reticulumEnableAllowed,
        ...(node.reticulum === undefined ? {} : { reticulum: node.reticulum }),
      }];
    }
    if (route === 'POST /manage/v1/settings') {
      let req;
      try {
        req = JSON.parse(body);
      } catch {
        return err(400, 'bad_request', 'The body is not JSON.');
      }
      if (!req || typeof req.changes !== 'object' || req.changes === null || typeof req.revision !== 'string') return err(400, 'bad_request', 'Needs revision and changes.');
      if (req.revision !== revision()) return err(409, 'stale_revision', 'The settings changed elsewhere.', { settings_revision: revision() });
      const applied = [];
      for (const [key, to] of Object.entries(req.changes)) {
        const field = known(key);
        if (!field) return err(403, 'not_allowed', 'That setting cannot be changed remotely.', { key });
        if (typeof to !== 'string' || to.length > 4096) return err(400, 'invalid_value', 'That value is not valid.', { key });
        if (field.access === 'turn_off_only' && to !== 'false') return err(403, 'not_allowed', 'That can only be turned off remotely.', { key });
        if (node.settings[key] !== to) applied.push({ key, from: node.settings[key], to });
      }
      if (applied.length === 0) return err(400, 'no_change', 'Nothing would change.');
      for (const c of applied) node.settings[c.key] = c.to;
      const id = newId();
      log('settings', actor, applied, id);
      return [200, { id, applied, notes: [], settings_revision: revision() }];
    }
    if (route === 'POST /manage/v1/restart') {
      if (node.restart?.state === 'restarting') return err(409, 'restarting', 'A restart is already running.');
      const id = newId();
      node.restart = { id, state: 'restarting', started: time(), problems: [] };
      log('restart', actor, [], id);
      return [202, { id, state: 'restarting' }];
    }
    if (route === 'POST /manage/v1/rollback') {
      let req;
      try {
        req = JSON.parse(body);
      } catch {
        return err(400, 'bad_request', 'The body is not JSON.');
      }
      const entry = node.audit.find((e) => e.id === req?.id && e.op === 'settings');
      if (!entry) return err(404, 'unknown_change', 'No such change.');
      const back = entry.changes.map((c) => ({ key: c.key, from: c.to, to: c.from }));
      const changed = back.filter((c) => node.settings[c.key] !== c.from).map((c) => c.key);
      if (changed.length) return err(409, 'changed_since', 'Changed since.', { keys: changed });
      if (back.some((c) => known(c.key)?.access === 'turn_off_only')) return err(403, 'not_allowed', 'That would turn a service on.');
      for (const c of back) node.settings[c.key] = c.to;
      const id = newId();
      log('rollback', actor, back, id);
      return [200, { id, applied: back }];
    }
    if (route === 'POST /manage/v1/reticulum') {
      let req;
      try {
        req = JSON.parse(body);
      } catch {
        return err(400, 'bad_request', 'The body is not JSON.');
      }
      if (!req || typeof req.revision !== 'string' || !Number.isInteger(req.confirm_seconds) || req.confirm_seconds < 60 || req.confirm_seconds > 900 || !Array.isArray(req.changes) || req.changes.length < 1 || req.changes.length > 16) return err(400, 'bad_request', 'Needs revision, confirm_seconds and 1 to 16 changes.');
      if (node.pending) return err(409, 'pending', 'Another change is pending.', { id: node.pending.id });
      if (node.restart?.state === 'restarting') return err(409, 'restarting', 'A restart is already running.');
      const ret = node.reticulum;
      if (req.revision !== ret?.revision) return err(409, 'stale_revision', 'The config changed.', { reticulum_revision: ret?.revision ?? '0'.repeat(32) });
      // Worked on a copy, so a refusal half way changes nothing.
      const work = structuredClone(ret);
      const applied = [];
      for (const c of req.changes) {
        const kind = Array.isArray(c?.path) && c.path.length === 1 && c.path[0] === 'reticulum' ? 'reticulum' : Array.isArray(c?.path) && c.path.length === 2 && c.path[0] === 'interfaces' && typeof c.path[1] === 'string' ? 'interfaces' : null;
        if (!kind || typeof c.key !== 'string' || typeof c.value !== 'string') return err(400, 'bad_request', 'A change is malformed.');
        const section = work.sections.find((x) => JSON.stringify(x.path) === JSON.stringify(c.path));
        if (!section) return err(404, 'unknown_section', 'No such section.', { path: c.path });
        const rule = RET_KEYS[kind][c.key];
        if (!rule || section.keys.some((k) => k.key === 'type' && k.value === 'PipeInterface')) return err(403, 'not_allowed', `${c.key} cannot be changed remotely.`, { path: c.path, key: c.key });
        if (!rule.ok(c.value)) return err(400, 'invalid_value', 'That is not a value for this setting.', { path: c.path, key: c.key });
        if (rule.ok === SWITCH && c.key !== 'ingress_control' && c.value === 'yes' && !node.reticulumEnableAllowed) return err(403, 'not_allowed', 'Turning this on remotely is not allowed on this node.', { path: c.path, key: c.key });
        const line = section.keys.find((k) => rule.names.includes(k.key));
        const from = line?.set ? (line.value ?? '(hidden)') : '';
        const same = line?.set && (rule.ok === SWITCH ? truthy(from) === truthy(c.value) : String(from).toLowerCase() === c.value);
        if (same) continue;
        if (line) Object.assign(line, { value: c.value, set: true });
        else section.keys.push({ key: c.key, value: c.value, set: true });
        applied.push({ path: c.path, key: c.key, from, to: c.value });
      }
      if (applied.length === 0) return err(400, 'no_change', 'Nothing would change.');
      work.revision = sha256(JSON.stringify(work.sections)).slice(0, 32);
      node.reticulumBefore = ret;
      node.reticulum = work;
      const id = newId();
      node.pending = { id, actor, state: 'restarting', applied_at: time(), confirm_seconds: req.confirm_seconds, healthy_at: null, confirm_by: null, changes: applied, problems: [] };
      log('reticulum', actor, applied, id);
      return [202, { id, state: 'restarting', confirm_seconds: req.confirm_seconds, applied, notes: [], reticulum_revision: work.revision }];
    }
    if (route === 'POST /manage/v1/confirm') {
      let req;
      try {
        req = JSON.parse(body);
      } catch {
        return err(400, 'bad_request', 'The body is not JSON.');
      }
      if (typeof req?.id !== 'string' || !/^[0-9a-f]{16}$/.test(req.id)) return err(400, 'bad_request', 'Needs an id.');
      node.onConfirm?.(req);
      const p = node.pending;
      if (!p || p.id !== req.id || p.state !== 'probation') return err(409, 'not_pending', 'That change is not on probation.', { state: p && p.id === req.id ? p.state : null });
      if (p.actor !== actor) return err(403, 'not_allowed', 'Only the user who made the change can confirm it.');
      node.finish('committed');
      log('confirm', actor, [], p.id);
      return [200, { id: p.id, state: 'committed' }];
    }
    if (route === 'GET /manage/v1/audit') {
      const before = Number(url.searchParams.get('before') ?? Infinity);
      const limit = Math.min(Math.max(Number(url.searchParams.get('limit') ?? 50) || 50, 1), 100);
      const older = node.audit.filter((e) => e.seq < before).reverse();
      return [200, { entries: older.slice(0, limit), more: older.length > limit }];
    }
    return err(404, 'bad_request', 'No such page.');
  }

  node.advance = (state) => {
    if (!node.pending) throw new Error('nothing is pending');
    node.pending.state = state;
    if (state === 'probation') {
      node.pending.healthy_at = time();
      node.pending.confirm_by = time() + node.pending.confirm_seconds;
    }
  };
  node.finish = (outcome, message = '') => {
    if (!node.pending) throw new Error('nothing is pending');
    if (outcome === 'rolled_back' && node.reticulumBefore) node.reticulum = node.reticulumBefore;
    node.reticulumResult = { id: node.pending.id, outcome, at: time(), message };
    if (outcome !== 'committed') log('auto_rollback', node.pending.actor, [], node.pending.id, outcome === 'rolled_back' ? 'rolled_back' : 'failed');
    node.pending = null;
    node.reticulumBefore = null;
  };

  const server = http.createServer((req, res) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size <= 16 * 1024) chunks.push(c);
    });
    req.on('end', () => {
      handle(req, res, Buffer.concat(chunks), size).catch(() => {
        res.destroy();
      });
    });
  });

  async function handle(req, res, bodyBytes, size) {
    const send = (status, text, signWith, nonce, extra = {}) => {
      const headers = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extra };
      if (signWith !== null) headers['X-Rettui-Signature'] = `v1=${hmac(signWith, `v1-response\n${nonce}\n${status}\n${sha256(text)}`)}`;
      res.writeHead(status, headers);
      res.end(text);
    };
    const plain = (status, obj) => send(status, JSON.stringify(obj), null, '');
    if (size > 16 * 1024) return plain(413, { error: 'too_large', message: 'Too large.' });
    const h = req.headers;
    const get = (name) => (typeof h[name] === 'string' ? h[name] : '');
    const [ts, nonce, actor, sig] = [get('x-rettui-timestamp'), get('x-rettui-nonce'), get('x-rettui-actor'), get('x-rettui-signature')];
    if (!HEADER_RE.ts.test(ts) || !HEADER_RE.nonce.test(nonce) || !HEADER_RE.actor.test(actor) || !HEADER_RE.sig.test(sig)) return plain(401, { error: 'unauthorised', message: 'Not signed.' });
    const canonical = `v1\n${ts}\n${nonce}\n${req.method}\n${req.url}\n${actor}\n${sha256(bodyBytes)}`;
    const good = crypto.timingSafeEqual(Buffer.from(hmac(secret, canonical), 'hex'), Buffer.from(sig.slice(3), 'hex'));
    node.requests.push({ method: req.method, path: req.url, actor, body: bodyBytes.toString('utf8'), signed: good, nonce });
    if (!good) return plain(401, { error: 'unauthorised', message: 'Not signed.' });

    const mode = node.misbehave;
    const reply = (status, obj, text = JSON.stringify(obj)) => {
      if (mode === 'unsigned') return send(status, text, null, nonce);
      return send(status, text, mode === 'wrong-signature' ? `${secret}-other` : secret, nonce);
    };
    if (Math.abs(Number(ts) - time()) > 300 || mode === 'clock_skew') {
      return reply(401, { error: 'clock_skew', message: 'Clocks differ.', node_time: mode === 'clock_skew' ? time() + 3600 : time() });
    }
    if (node.seen.has(nonce)) return reply(401, { error: 'unauthorised', message: 'Repeated.' });
    node.seen.add(nonce);

    if (mode === 'slow') await new Promise((resolve) => setTimeout(resolve, slowMs));
    if (mode === 'redirect') return send(302, '', null, nonce, { Location: '/manage/v1/state' });
    if (mode === 'oversize') return reply(200, null, JSON.stringify({ pad: 'x'.repeat(70 * 1024) }));
    if (mode === 'bad-json') return reply(200, null, 'not json');
    if (mode === 'array') return reply(200, null, '[1,2]');
    if (mode === 'bad-node-time') return reply(200, { v: 1, node_time: 'soon' });
    if (mode === 'control-chars') return reply(200, null, `{"v":1,"node_time":${time()},"version":"\\u202e2.5\\u0000.0\\u200b","\\u200bk":"a\\nb","nested":{"list":["\\u0007x"]},"__proto__":{"x":1}}`);
    const [status, obj] = answer(req.method, req.url, actor, bodyBytes.toString('utf8'));
    return reply(status, obj);
  }

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  node.url = `http://127.0.0.1:${server.address().port}`;
  node.close = () =>
    new Promise((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  return node;
}
