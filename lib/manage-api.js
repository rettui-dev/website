// The manage API behind the /manage page: what the rettui nodes set up for remote management
// (manage_url and manage_secret_file in the config file) say about themselves, and the few changes
// the website may make on them (settings from the node's allow-list, a Reticulum restart, rolling
// back the last settings change). For users with the role manage or admin only.
//
// The website signs every request to a node with that node's own secret (lib/manage.js), and the
// node signs its answer. The secret never leaves the client made by createManageClient: it is not
// in an answer here, a log line, an error or audit.log. What a node says is untrusted: every text is
// cleaned and cut to length here before it reaches the page, which sets it as text only.
//
// Reading needs a session with the role manage or admin (rechecked on every request) and is
// limited per user and node. Every change also needs, as on the users page (admin.js): a POST of
// JSON from the page itself (the request header, same origin, JSON, at most 16 KiB), a sign in from
// the last 15 minutes, a second factor turned on for the account (a user without one can look but
// not change anything: 403, second-factor-required), that factor not being the first one turned on in
// the last 24 hours (factor-hold.js: 403, second-factor-new), and the password with the passkey, app
// code or recovery code in the request itself (confirmBoth). Changes are limited per user per hour,
// wrong passwords and codes included. Right before the node is asked, the session must still be
// there and still have the role. The node gets the user's stored name as the actor, and writes
// its own audit log with the values; the website's audit.log gets one line per change asked of a
// node, manage-settings, manage-restart, manage-rollback or manage-reticulum, with the keys and the
// node's change id, never the values.
//
// A Reticulum config change (/api/manage/reticulum) goes through the same checks. The node applies
// it, restarts Reticulum and keeps the change on probation: unless the website confirms it in time,
// the node puts the old config back by itself. The confirm job (manage-confirm.js) does that, once it
// can still reach the node; GET /api/manage/confirm says how that job is going.
//
// What a node answers with an error becomes one of a few fixed sentences here; only the words of
// invalid_value, not_allowed and ambiguous are passed on (cleaned, at most 300 characters), since
// they say which value the node refused and why.
import { cleanText } from './propagation.js';
import { clientIp, waitText } from './login.js';
import { Budget, CHANGE_PASSWORD_FIRST, GONE, RECENT_AUTH_MS, createStepUp, isMap, readJsonChange, recentSignIn } from './account.js';
import { createFactorHolds } from './factor-hold.js';

export const MANAGE_PATHS = ['/api/manage/settings', '/api/manage/restart', '/api/manage/rollback', '/api/manage/reticulum'];
// Changes one user may ask of the nodes in an hour, wrong passwords and codes included.
export const MANAGE_WRITES_PER_USER = 30;
// Reads (the state of a node, its audit log) one user may make of one node in an hour.
export const MANAGE_READS_PER_NODE = 120;
// Questions about the confirm jobs one user may ask in an hour (the page asks every 3 seconds while
// a job runs). They never reach a node.
export const MANAGE_CONFIRM_READS_PER_USER = 1200;
// A node's clock this far off is worth a warning; the node refuses requests from 300 seconds.
export const SKEW_WARNING_SECONDS = 60;
// What the node's wire API allows in one change (see the node's /manage/v1/settings).
export const MAX_CHANGES = 32;
export const MAX_VALUE_BYTES = 4096;
// How much of a node's message is passed on.
export const MAX_NODE_MESSAGE = 300;
// What the node's wire API allows in one Reticulum change (see the node's /manage/v1/reticulum).
export const MAX_RET_CHANGES = 16;
export const MAX_RET_VALUE_BYTES = 32;
export const MAX_INTERFACE_NAME_BYTES = 64;
// How long the node waits for the confirm when the config file gives no figure.
export const DEFAULT_CONFIRM_SECONDS = 300;
const MANAGE_ROLES = new Set(['manage', 'admin']);
const REVISION_RE = /^[0-9a-f]{32}$/;
const CHANGE_ID_RE = /^[0-9a-f]{16}$/;
const KEY_RE = /^[a-z][a-z0-9_]{0,63}$/;
const KINDS = new Set(['text', 'optional', 'number', 'toggle', 'choice']);
const ACCESS = new Set(['change', 'turn_off_only']);
const NETWORK_STATES = new Set(['starting', 'running', 'failed']);
const RESTART_STATES = new Set(['restarting', 'up', 'unhealthy']);
const AUDIT_OPS = new Set(['settings', 'restart', 'rollback', 'reticulum', 'confirm', 'auto_rollback', 'auth_failures']);
const AUDIT_RESULTS = new Set(['ok', 'refused', 'failed', 'rolled_back']);
const PENDING_STATES = new Set(['restarting', 'probation', 'rolling_back']);
// The node's own checks of a pending change, per interface: a self test (does Reticulum answer a
// test request on it) or whether it is online and sees traffic. Each kind with the results it can have.
const CHECK_RESULTS = { self_test: new Set(['waiting', 'passed', 'failed']), online: new Set(['waiting', 'traffic', 'no_traffic', 'failed']) };
const MAX_CHECKS = 32;
const MAX_AUDIT_NOTES = 16;
const RESULT_OUTCOMES = new Set(['committed', 'rolled_back', 'rollback_failed', 'left']);
const MAX_SETTINGS = 64;
const MAX_CHOICES = 32;
const MAX_PROBLEMS = 32;
const MAX_AUDIT_ENTRIES = 100;
// The read-only Reticulum config of a node: how much of it is kept, and how long a text may be.
const MAX_RET_SECTIONS = 128;
const MAX_RET_KEYS = 64;
const MAX_RET_PATH = 4;
const MAX_RET_TEXT = 256;
// The sections the node says the website may change: [reticulum] and at most 32 interfaces.
const MAX_EDITABLE = 33;
// How much of an old or new value of a Reticulum change is kept.
const MAX_RET_CHANGE_VALUE = 64;

// The Reticulum settings the node lets the website change, by the kind of section, each with the
// rule for its value (the node's table; it checks again). Only these names are sent: the node
// edits an alias it finds in the file (interface_enabled, interface_mode) itself.
export const RET_EDITS = {
  reticulum: { enable_transport: 'switch' },
  interfaces: { enabled: 'switch', mode: 'mode', announce_cap: 'cap', bitrate: 'bitrate', ingress_control: 'switch' },
};
export const RET_MODES = ['full', 'gateway', 'access_point', 'roaming', 'boundary'];
// The settings whose yes turns something on (an interface, which may open a port, or transport):
// only when the node allows it (reticulum_enable_allowed).
export const RET_TURNS_ON = new Set(['enabled', 'enable_transport']);
const CAP_RE = /^(0|[1-9][0-9]?|100)(\.[0-9]{1,2})?$/;
const BITRATE_RE = /^[1-9][0-9]{0,10}$/;
const RULE_OK = {
  switch: (v) => v === 'yes' || v === 'no',
  mode: (v) => RET_MODES.includes(v),
  cap: (v) => CAP_RE.test(v) && Number(v) > 0 && Number(v) <= 100,
  bitrate: (v) => BITRATE_RE.test(v) && Number(v) >= 5 && Number(v) <= 10_000_000_000,
};
const RULE_TEXT = {
  switch: 'must be yes or no',
  mode: `must be one of ${RET_MODES.join(', ')}`,
  cap: 'must be a percentage above 0 and at most 100, with at most two decimals',
  bitrate: 'must be a whole number of bits per second from 5 to 10000000000',
};
// Whether a value passes the rule (switch, mode, cap or bitrate) of a Reticulum setting.
export const retValueOk = (rule, v) => typeof v === 'string' && Buffer.byteLength(v) <= MAX_RET_VALUE_BYTES && Object.hasOwn(RULE_OK, rule) && RULE_OK[rule](v);
// Characters that cannot be in an interface name the node takes: control and format characters
// (direction marks, zero-width ones), line and paragraph separators, and what the config syntax uses.
const NAME_BAD_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}[\]#"']/u;
// Whether an interface name is one the node takes in a change: 1 to 64 bytes, no space at either
// end, none of the characters above.
export function interfaceNameOk(name) {
  if (typeof name !== 'string') return false;
  const bytes = Buffer.byteLength(name);
  return bytes >= 1 && bytes <= MAX_INTERFACE_NAME_BYTES && name === name.trim() && !NAME_BAD_RE.test(name) && cleanText(name, MAX_INTERFACE_NAME_BYTES) === name;
}
// The kind of section a path names, as the node takes it: 'reticulum' for ["reticulum"],
// 'interfaces' for ["interfaces", name]; null otherwise.
export function retPathKind(path) {
  if (!Array.isArray(path)) return null;
  if (path.length === 1 && path[0] === 'reticulum') return 'reticulum';
  if (path.length === 2 && path[0] === 'interfaces' && interfaceNameOk(path[1])) return 'interfaces';
  return null;
}
const samePath = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

export const NOT_MANAGER = { error: 'Only users with the manage or admin role can manage nodes.' };
export const NO_NODE = { error: 'There is no such node. Reload the page.' };
export const SECOND_FACTOR_REQUIRED = { error: 'Turn on two-step sign-in on your account page before you change anything on a node. Until then you can only look.', code: 'second-factor-required' };

// The warning, or the refusal, about a node clock that is off. minutes is at least 1.
export function skewText(minutes) {
  return `This node's clock is ${minutes} ${minutes === 1 ? 'minute' : 'minutes'} off from the website's, so signed requests can't be trusted; fix the node's time.`;
}
// The refusal while the wait after a first second factor runs (until: ms). what: 'nodes', or
// 'users' for the users page.
export function secondFactorNew(until, t, what = 'nodes') {
  const from = new Date(until).toISOString();
  return {
    error: `Your two-step sign-in was turned on less than 24 hours ago, so you can change ${what} in ${waitText(until - t)} (from ${from}). Until then you can only look. This keeps a stolen password from being enough to change ${what === 'nodes' ? 'a node' : 'users'}.`,
    code: 'second-factor-new',
    nodeChangesFrom: from,
  };
}
const skewMinutes = (seconds) => Math.max(1, Math.round(Math.abs(seconds) / 60));

// Why the website could not use a node's answer (the errors of client.call): [status, text].
const CALL_FAILED = {
  'unknown-node': [404, NO_NODE.error],
  timeout: [504, 'The node did not answer in time, so nothing is known to be done. Check the node, then reload the page.'],
  network: [502, 'The node could not be reached. Check that it is running and that the website can reach its manage address.'],
  'too-large': [502, 'The node sent an answer that is too large, so it was not used.'],
  invalid: [502, 'The node sent an answer that could not be read, so it was not used.'],
  // A wrong secret on either side, or an answer that did not come from the node: the node signs
  // nothing it refuses before it has checked the signature.
  unsigned: [502, 'The node did not answer with a valid signature: check the secret file on both sides.'],
};
// For a change, an unsigned answer is also what a node gives a request it has seen before, or one
// that took too long to arrive: the change may have been made all the same.
const UNSIGNED_WRITE = [502, "The node's answer could not be checked, so it is not known whether the change was made. Reload the node to see, before you try again."];
// A node takes no request signed before it last started (and a little while after): before_start.
// How long the website waits at most on what a node says about that.
export const MAX_RESTART_WAIT_SECONDS = 600;
export function restartedText(seconds) {
  return seconds > 0 ? `The node restarted moments ago, so it did not take this request. Try again in ${waitText(seconds * 1000)}.` : 'The node restarted moments ago, so it did not take this request. Try again.';
}

// What the node refused, by its error code: [status, text]. invalid_value and not_allowed pass the
// node's own message on instead, when it has one.
const NODE_REFUSED = {
  unauthorised: [502, 'The node did not accept the signature of the website. Check that the node and the website use the same manage secret.'],
  bad_request: [400, 'The node could not use this request. Reload the page and try again.'],
  invalid_value: [400, 'The node did not accept a value.'],
  no_change: [400, 'Nothing was changed: the node has these values already.'],
  not_allowed: [403, 'The node does not allow this change from the website.'],
  stale_revision: [409, 'The settings were changed elsewhere since the page loaded them. They are loaded again: check them, then save again.'],
  busy: [409, 'The node is busy with another change. Try again in a moment.'],
  restarting: [409, 'Reticulum is restarting on this node already. Wait until it is back.'],
  changed_since: [409, 'A setting of that change was changed again since, so it cannot be rolled back. Change it by hand.'],
  unknown_change: [404, 'The node does not know that change, so it cannot be rolled back.'],
  shared_instance: [409, 'This node uses a shared Reticulum instance, so that cannot be done from here.'],
  too_large: [400, 'The change is too large for the node.'],
  rate_limited: [429, 'The node is limiting changes right now.'],
  stamping: [429, "The node is still making its announce stamp, so it can't test a Reticulum change yet. Nothing was changed."],
  queue_full: [503, 'The node is busy. Try again in a moment.'],
  nonce_cache_full: [503, 'The node is busy. Try again in a moment.'],
  timeout: [504, 'The node did not finish in time, so nothing is known to be done. Reload the page to see what it did.'],
  pending: [409, 'Another Reticulum change on this node is still being tested. Wait until it is kept or rolled back.'],
  not_pending: [409, 'That Reticulum change is no longer waiting to be kept.'],
  ambiguous: [409, 'The node cannot tell for sure which line of its Reticulum config to change, so it changed nothing. Change it in the terminal.'],
  unknown_section: [404, 'The node has no such section. Reload the page.'],
  failed: [502, 'The node could not save the change, so nothing was changed.'],
};
// A stale revision of a Reticulum change: the view is loaded again.
const STALE_RETICULUM = 'The Reticulum configuration was changed elsewhere since the page loaded it. It is loaded again: check it, then apply again.';
// The codes whose own words of the node are passed on, and those that name a section.
const NODE_WORDS = new Set(['invalid_value', 'not_allowed', 'ambiguous']);
const NODE_PATH = new Set(['invalid_value', 'not_allowed', 'ambiguous', 'unknown_section']);
const NODE_OTHER = [502, 'The node answered with an error. Try again later.'];

// ---- cleaning what a node says ----

const text = (v, max) => cleanText(v, max) ?? '';
const whole = (v, min, max) => (Number.isSafeInteger(v) && v >= min && v <= max ? v : null);
const hexOr = (v, re) => (typeof v === 'string' && re.test(v) ? v : null);
const listOf = (v, max) => (Array.isArray(v) ? v.slice(0, max) : []);
// A setting's value as text: the node sends text, but a number or a true/false is read too.
function valueText(v) {
  if (typeof v === 'string') return text(v, MAX_VALUE_BYTES);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return '';
}
const keyOf = (v) => (typeof v === 'string' && KEY_RE.test(v) ? v : null);
const keyList = (v) => listOf(v, MAX_CHANGES).map(keyOf).filter((k) => k !== null);
// A section path of the node's: 1 to 4 parts of text, none empty once cleaned; or null.
function pathOf(v) {
  if (!Array.isArray(v) || v.length === 0 || v.length > MAX_RET_PATH || !v.every((p) => typeof p === 'string')) return null;
  const path = v.map((p) => text(p, MAX_RET_TEXT));
  return path.some((p) => p === '') ? null : path;
}
// One change of a list: {key, from, to}, and for a Reticulum change its section first. Of a Reticulum
// key that is not on the list of shown ones, the values are hidden, as in the config view.
function changeOf(c) {
  if (!isMap(c)) return null;
  const key = keyOf(c.key);
  if (key === null) return null;
  const out = { key, from: valueText(c.from), to: valueText(c.to) };
  if (c.path === undefined || (Array.isArray(c.path) && c.path.length === 0)) return out;
  const path = pathOf(c.path);
  if (path === null) return null;
  const shown = RET_SHOWN.has(key);
  const value = (v) => (v === '' ? '' : shown ? v.slice(0, MAX_RET_CHANGE_VALUE) : '(hidden)');
  return { path, key, from: value(out.from), to: value(out.to) };
}
const changeList = (v, max = MAX_CHANGES) => listOf(v, max).map(changeOf).filter((c) => c !== null);

// One setting of /state, or null when it cannot be shown.
function settingOf(s) {
  if (!isMap(s)) return null;
  const key = keyOf(s.key);
  if (key === null || !ACCESS.has(s.access)) return null;
  const kind = KINDS.has(s.kind) ? s.kind : 'text';
  const out = { key, label: text(s.label, 80) || key, help: text(s.help, 500), kind, access: s.access, value: valueText(s.value) };
  if (kind === 'choice') out.choices = listOf(s.choices, MAX_CHOICES).map((c) => text(c, 100)).filter(Boolean);
  // A group the node may name; without one the page groups by the key.
  const section = text(s.section ?? s.group, 48);
  if (section) out.section = section;
  return out;
}

// The keys whose value may be shown. The node masks the rest, and the website does it again here:
// every other key only says whether it is set.
const RET_SHOWN = new Set(['type', 'enabled', 'interface_enabled', 'mode', 'interface_mode', 'announce_cap', 'bitrate', 'ingress_control', 'enable_transport', 'share_instance', 'listen_ip', 'listen_port', 'target_host', 'target_port', 'reachable_on', 'discoverable']);
// A section that runs a program (a pipe interface, or a command key) shows only these keys.
const RET_PROGRAM_KEEP = new Set(['type', 'enabled']);
const RET_PROGRAM_KEYS = new Set(['location_cmd', 'command']);

// One section of the Reticulum config, or null when it cannot be shown (no path, a path of more than
// four parts or with an empty part, no keys list). A key without a name, or without true or false
// for set, or with a value that is not text or null, is left out. Gives {section, cut}: cut is true
// when keys were left out for being too many.
function retSectionOf(s) {
  if (!isMap(s) || !Array.isArray(s.path) || s.path.length === 0 || s.path.length > MAX_RET_PATH || !Array.isArray(s.keys)) return null;
  const path = s.path.map((p) => text(p, MAX_RET_TEXT));
  if (path.some((p) => p === '')) return null;
  // Whether the path is shown as the node sent it: only such a section can be named in a change.
  const exact = path.every((p, i) => p === s.path[i]);
  let keys = [];
  for (const k of listOf(s.keys, MAX_RET_KEYS)) {
    if (!isMap(k) || typeof k.set !== 'boolean' || (k.value !== null && typeof k.value !== 'string')) continue;
    const name = text(k.key, MAX_RET_TEXT);
    if (name === '') continue;
    keys.push({ key: name, value: k.value === null ? null : text(k.value, MAX_RET_TEXT), set: k.set });
  }
  const lower = (k) => k.key.toLowerCase();
  const type = keys.find((k) => lower(k) === 'type');
  const program = /pipe/i.test(type?.value ?? '') || keys.some((k) => RET_PROGRAM_KEYS.has(lower(k)));
  if (program) keys = keys.filter((k) => RET_PROGRAM_KEEP.has(lower(k)));
  // A key that is not on the list, or that is not set, has no value here whatever the node said.
  keys = keys.map((k) => (k.set && RET_SHOWN.has(lower(k)) ? k : { ...k, value: null }));
  return { section: { path, keys }, cut: s.keys.length > MAX_RET_KEYS, program, exact };
}

// The sections the website may offer to change, of those the node lists as editable: each must
// be a path the node takes in a change, a section of the view here whose path the cleaning left as
// the node sent it (else the name shown is not the one the node would find), and not one that runs
// a program. None at all
// when the node uses a shared instance or says its view is cut. Each path once, at most 33.
function editableOf(r, parts) {
  if (r.shared_instance === true || r.truncated === true || !Array.isArray(r.editable)) return [];
  const out = [];
  for (const p of listOf(r.editable, MAX_EDITABLE)) {
    if (retPathKind(p) === null || out.some((q) => samePath(q, p))) continue;
    const at = parts.find((x) => samePath(x.section.path, p));
    if (at && at.exact && !at.program) out.push([...p]);
  }
  return out;
}

// What the node says about its Reticulum config, or null when it says nothing usable. truncated is
// true when the node says so, or when sections or keys were cut here.
export function cleanReticulum(r) {
  if (!isMap(r) || !Array.isArray(r.sections)) return null;
  const parts = listOf(r.sections, MAX_RET_SECTIONS).map(retSectionOf).filter((x) => x !== null);
  return {
    revision: hexOr(r.revision, REVISION_RE) ?? '',
    shared_instance: r.shared_instance === true,
    truncated: r.truncated === true || r.sections.length > MAX_RET_SECTIONS || parts.some((x) => x.cut),
    sections: parts.map((x) => x.section),
    editable: editableOf(r, parts),
  };
}

// The Reticulum change a node has pending, or null. A state the website does not know is said as
// 'unknown' (the change is still pending all the same).
export function cleanPending(p) {
  if (!isMap(p)) return null;
  const id = hexOr(p.id, CHANGE_ID_RE);
  if (id === null) return null;
  return {
    id,
    actor: text(p.actor, 32),
    state: PENDING_STATES.has(p.state) ? p.state : 'unknown',
    applied_at: whole(p.applied_at, 0, 1e11),
    confirm_seconds: whole(p.confirm_seconds, 1, 86_400),
    healthy_at: whole(p.healthy_at, 0, 1e11),
    confirm_by: whole(p.confirm_by, 0, 1e11),
    changes: changeList(p.changes, MAX_RET_CHANGES),
    problems: listOf(p.problems, MAX_PROBLEMS).map((x) => text(x, 200)).filter(Boolean),
    checks: listOf(p.checks, MAX_CHECKS).map(checkOf).filter((c) => c !== null),
  };
}

// An interface name of the node's, for display: cleaned and cut to 64 bytes, or null when nothing is left.
function interfaceText(v) {
  let name = text(v, MAX_INTERFACE_NAME_BYTES);
  while (Buffer.byteLength(name) > MAX_INTERFACE_NAME_BYTES) name = name.slice(0, -1);
  return name.trim() || null;
}

// One check of a pending change, or null when its kind, its result for that kind or its name is not
// one the website knows.
function checkOf(c) {
  if (!isMap(c) || typeof c.kind !== 'string' || !Object.hasOwn(CHECK_RESULTS, c.kind) || !CHECK_RESULTS[c.kind].has(c.result)) return null;
  const name = interfaceText(c.interface);
  return name === null ? null : { interface: name, kind: c.kind, result: c.result };
}

// How the node's last Reticulum change ended, or null.
export function cleanResult(r) {
  if (!isMap(r)) return null;
  const id = hexOr(r.id, CHANGE_ID_RE);
  if (id === null) return null;
  return { id, outcome: RESULT_OUTCOMES.has(r.outcome) ? r.outcome : 'unknown', at: whole(r.at, 0, 1e11), message: text(r.message, MAX_NODE_MESSAGE) };
}

export function cleanState(body) {
  const b = isMap(body) ? body : {};
  const net = isMap(b.network) ? b.network : {};
  const r = isMap(b.restart) ? b.restart : null;
  const keys = new Set();
  const settings = [];
  for (const s of listOf(b.settings, MAX_SETTINGS)) {
    const one = settingOf(s);
    // A key twice is shown once: the first.
    if (one && !keys.has(one.key)) {
      keys.add(one.key);
      settings.push(one);
    }
  }
  return {
    node_time: whole(b.node_time, 0, 1e11),
    version: text(b.version, 32),
    settings_revision: hexOr(b.settings_revision, REVISION_RE) ?? '',
    settings,
    network: {
      state: NETWORK_STATES.has(net.state) ? net.state : 'unknown',
      shared_instance: net.shared_instance === true,
      interfaces_total: whole(net.interfaces_total, 0, 100_000),
      interfaces_online: whole(net.interfaces_online, 0, 100_000),
    },
    restart: r && hexOr(r.id, CHANGE_ID_RE) ? { id: r.id, state: RESTART_STATES.has(r.state) ? r.state : 'unknown', started: whole(r.started, 0, 1e11), problems: listOf(r.problems, MAX_PROBLEMS).map((p) => text(p, 200)).filter(Boolean) } : null,
    restart_allowed_at: whole(b.restart_allowed_at, 0, 1e11),
    reticulum: cleanReticulum(b.reticulum),
    pending: cleanPending(b.pending),
    reticulum_result: cleanResult(b.reticulum_result),
    // Whether the node lets the website turn an interface or transport on. Without a clear yes, no.
    reticulum_enable_allowed: b.reticulum_enable_allowed === true,
  };
}

export function cleanAudit(body) {
  const b = isMap(body) ? body : {};
  const entries = listOf(b.entries, MAX_AUDIT_ENTRIES)
    .filter(isMap)
    .map((e) => ({
      seq: whole(e.seq, 0, Number.MAX_SAFE_INTEGER),
      time: whole(e.time, 0, 1e11),
      id: hexOr(e.id, CHANGE_ID_RE),
      actor: text(e.actor, 32),
      op: AUDIT_OPS.has(e.op) ? e.op : 'other',
      changes: changeList(e.changes),
      result: AUDIT_RESULTS.has(e.result) ? e.result : 'other',
      error: typeof e.error === 'string' ? text(e.error, MAX_NODE_MESSAGE) : null,
      // What the node checked (confirm, auto_rollback): one text or a list of them.
      notes: (typeof e.notes === 'string' ? [e.notes] : listOf(e.notes, MAX_AUDIT_NOTES)).map((n) => text(n, MAX_NODE_MESSAGE)).filter(Boolean),
    }))
    .filter((e) => e.seq !== null);
  return { entries, more: b.more === true };
}

// ---- the API ----

// auth: what createLogin gives. client: what createManageClient gives (call(host, method, path,
// actor, body?), confirmSeconds(host)), or null without nodes to manage. nodes: [{host, name}] of the
// nodes that have a manage_url, in the order of the config file. now: the clock of the sessions;
// wallClock: the real time, which a node's clock is compared with. holds: the waits after a first
// second factor (factor-hold.js), shared with the account API. confirmJobs: what createConfirmJobs
// gives (manage-confirm.js), which keeps a Reticulum change once the node can still be reached; null
// without it.
export function createManageApi({ auth, client = null, nodes = [], now = Date.now, wallClock = Date.now, log = console.error, holds = createFactorHolds({ now }), confirmJobs = null }) {
  const store = auth.store;
  const audit = auth.audit;
  const known = new Map(nodes.map((n) => [n.host.toLowerCase(), { host: n.host.toLowerCase(), name: n.name ?? n.host }]));
  const writes = new Budget({ limit: MANAGE_WRITES_PER_USER, now });
  const reads = new Budget({ limit: MANAGE_READS_PER_NODE, now });
  const confirmReads = new Budget({ limit: MANAGE_CONFIRM_READS_PER_USER, now });
  // How long the node is asked to wait for the confirm (manage_confirm_seconds), 60 to 900 seconds.
  const confirmSecondsOf = (host) => {
    const v = typeof client?.confirmSeconds === 'function' ? client.confirmSeconds(host) : null;
    return Number.isInteger(v) && v >= 60 && v <= 900 ? v : DEFAULT_CONFIRM_SECONDS;
  };
  const jobOf = (host) => (confirmJobs ? confirmJobs.status(host) : null);
  // Per node, whether it said last that the website may turn things on (reticulum_enable_allowed).
  // Until it said so, a change that turns something on is refused here; the node checks again.
  const enableAllowed = new Map();
  const { confirmBoth } = createStepUp(auth);
  const allowedRole = (role) => MANAGE_ROLES.has(role);

  // The session of a request: {cur} for a manage or admin user; {status, body} otherwise.
  function access(req) {
    const cur = auth.session(req);
    if (!cur) return { status: 401, body: { error: 'Sign in first.', signIn: true } };
    if (!allowedRole(cur.user.role)) return { status: 403, body: NOT_MANAGER };
    if (cur.user.mustChangePassword) return { status: 403, body: CHANGE_PASSWORD_FIRST };
    return { cur };
  }

  // Whether the page may be served to this request.
  const pageAllowed = (req) => Boolean(access(req).cur);

  const tooOften = (json, wait, what) => {
    const sec = Math.ceil(wait / 1000);
    return json(429, { error: `${what} Try again in ${waitText(wait)}.`, retryAfter: sec }, { 'Retry-After': String(sec) });
  };

  // Asks the node; a client that throws is a bug, and is said like a node that cannot be reached.
  async function ask(host, method, target, actor, body) {
    if (!client) return { ok: false, error: 'unknown-node' };
    try {
      return await client.call(host, method, target, actor, body);
    } catch {
      log(`manage: the request to ${host} failed unexpectedly`);
      return { ok: false, error: 'network' };
    }
  }

  // Per node, the time (in seconds, as the website signs) that a request must be signed after,
  // when the node answered before_start: until then a change is refused here before the step-up,
  // so that trying again too soon uses up no code.
  const restarted = new Map();
  const nowSeconds = () => Math.floor(wallClock() / 1000);
  // Seconds left to wait for a node, or 0.
  function restartWait(host) {
    const after = restarted.get(host);
    if (after === undefined) return 0;
    const left = after + 1 - nowSeconds();
    if (left <= 0) restarted.delete(host);
    return Math.max(0, left);
  }
  const restartAnswer = (seconds) => {
    const wait = Math.max(1, seconds);
    return { status: 503, body: { error: restartedText(seconds), code: 'before_start', retryAfter: wait }, code: 'before_start', headers: { 'Retry-After': String(wait) } };
  };

  // The answer for a call that did not give a usable 2xx: {status, body, code, headers?}. host: the
  // node asked; write: whether it was a change; op: which change.
  function failure(r, host, write = false, op = null) {
    if (!r.ok && r.error === 'unsigned' && write) return { status: UNSIGNED_WRITE[0], body: { error: UNSIGNED_WRITE[1], code: 'unsigned' }, code: 'unsigned' };
    if (r.ok && isMap(r.body) && r.body.error === 'before_start') {
      const after = whole(r.body.signed_after, 0, 1e11);
      if (after === null) return restartAnswer(0);
      // Bounded, so a node cannot hold the website off for long.
      restarted.set(host, Math.min(after, nowSeconds() + MAX_RESTART_WAIT_SECONDS));
      return restartAnswer(restartWait(host));
    }
    if (!r.ok) {
      if (r.error === 'clock') {
        const minutes = skewMinutes(Number.isFinite(r.skewSeconds) ? r.skewSeconds : 300);
        return { status: 502, body: { error: skewText(minutes), code: 'clock', clock: { skewMinutes: minutes } }, code: 'clock' };
      }
      const code = typeof r.error === 'string' && Object.hasOwn(CALL_FAILED, r.error) ? r.error : 'network';
      const [status, error] = CALL_FAILED[code];
      return { status, body: { error, code }, code };
    }
    const b = isMap(r.body) ? r.body : {};
    // The client says 'clock' for this; a node's clock_skew is read here all the same.
    if (b.error === 'clock_skew') {
      const nodeTime = whole(b.node_time, 0, 1e11);
      const minutes = skewMinutes(nodeTime === null ? 300 : nodeTime - wallClock() / 1000);
      return { status: 502, body: { error: skewText(minutes), code: 'clock', clock: { skewMinutes: minutes } }, code: 'clock' };
    }
    const code = typeof b.error === 'string' && Object.hasOwn(NODE_REFUSED, b.error) ? b.error : null;
    if (code === null) return { status: NODE_OTHER[0], body: { error: NODE_OTHER[1], code: 'node-error' }, code: 'node-error' };
    let [status, error] = NODE_REFUSED[code];
    const body = { code };
    const headers = {};
    if (NODE_WORDS.has(code)) {
      error = text(b.message, MAX_NODE_MESSAGE) || error;
      const key = keyOf(b.key);
      if (key) body.key = key;
    }
    if (NODE_PATH.has(code)) {
      const path = pathOf(b.path);
      if (path) body.path = path;
    }
    if (code === 'changed_since') body.keys = keyList(b.keys);
    if (code === 'stale_revision' && op === 'reticulum') {
      error = STALE_RETICULUM;
      const rev = hexOr(b.reticulum_revision, REVISION_RE);
      if (rev) body.reticulumRevision = rev;
    } else if (code === 'stale_revision') {
      const rev = hexOr(b.settings_revision, REVISION_RE);
      if (rev) body.settingsRevision = rev;
    }
    if (code === 'pending') {
      const id = hexOr(b.id, CHANGE_ID_RE);
      if (id) body.id = id;
    }
    if (code === 'not_pending') body.state = PENDING_STATES.has(b.state) ? b.state : null;
    if (code === 'rate_limited' || code === 'stamping') {
      // A stamping node never asks for more than a minute.
      const sec = whole(b.retry_after, 1, code === 'stamping' ? 60 : 3600) ?? 60;
      error = `${error} Try again in ${waitText(sec * 1000)}.`;
      body.retryAfter = sec;
      headers['Retry-After'] = String(sec);
    }
    return { status, body: { error, ...body }, code, headers };
  }

  // The node a request names (?host= or the body's host), or null.
  const nodeOf = (value) => (typeof value === 'string' && value.length <= 300 ? (known.get(value.toLowerCase()) ?? null) : null);

  // GET /api/manage
  function get(req, json) {
    const a = access(req);
    if (!a.cur) return json(a.status, a.body);
    const name = a.cur.user.name;
    const s = a.cur.session;
    const recent = recentSignIn(s, now());
    const held = holds.until(name);
    return json(200, {
      me: name,
      roleOk: true,
      // Without a second factor this user can look, but not change anything.
      secondFactor: store.secondFactorEnabled(name),
      // While the wait after a first second factor runs, neither: the time it ends.
      nodeChangesFrom: held === null ? null : new Date(held).toISOString(),
      stepUpMethods: auth.methodsFor(name),
      recentSignIn: recent,
      recentUntil: recent ? new Date(s.authAt + RECENT_AUTH_MS).toISOString() : null,
      nodes: [...known.values()],
    });
  }

  // The checks of a read: access, a known node, the budget. Gives {cur, node} or answers.
  function readable(req, json, host, head) {
    const a = access(req);
    if (!a.cur) return json(a.status, a.body);
    const node = nodeOf(host);
    if (!node) return json(404, NO_NODE);
    // A HEAD request checks access only; it never costs the node a request.
    if (head) return json(200, {});
    const key = `user:${a.cur.user.name.toLowerCase()} ${node.host}`;
    const wait = reads.wait(key);
    if (wait > 0) return tooOften(json, wait, 'You asked this node too often.');
    reads.take(key);
    return { cur: a.cur, node };
  }

  // GET /api/manage/node?host=
  async function getNode(req, searchParams, json, head = false) {
    const ok = readable(req, json, searchParams.get('host'), head);
    if (!ok?.cur) return;
    const r = await ask(ok.node.host, 'GET', '/manage/v1/state', ok.cur.user.name);
    if (!r.ok || r.status !== 200) {
      const f = failure(r, ok.node.host);
      return json(f.status, f.body, f.headers);
    }
    const state = cleanState(r.body);
    enableAllowed.set(ok.node.host, state.reticulum_enable_allowed);
    // confirm: how the website's confirm job for this node is going; confirmSeconds: how long a
    // Reticulum change waits for it.
    const out = { host: ok.node.host, name: ok.node.name, ...state, confirm: jobOf(ok.node.host), confirmSeconds: confirmSecondsOf(ok.node.host), skewSeconds: null };
    if (state.node_time !== null) {
      // The client's figure is measured against the time it signed with; this is the same clock.
      const skew = Number.isFinite(r.skewSeconds) ? Math.round(r.skewSeconds) : Math.round(state.node_time - wallClock() / 1000);
      out.skewSeconds = skew;
      if (Math.abs(skew) >= SKEW_WARNING_SECONDS) out.clock = { skewMinutes: skewMinutes(skew), warning: skewText(skewMinutes(skew)) };
    }
    return json(200, out);
  }

  // GET /api/manage/audit?host=&before=&limit=
  async function getAudit(req, searchParams, json, head = false) {
    const before = searchParams.get('before');
    const limit = searchParams.get('limit');
    if (before !== null && !/^\d{1,15}$/.test(before)) return json(400, { error: 'before must be an entry number.' });
    if (limit !== null && (!/^\d{1,3}$/.test(limit) || Number(limit) < 1 || Number(limit) > 100)) return json(400, { error: 'limit must be a whole number from 1 to 100.' });
    const ok = readable(req, json, searchParams.get('host'), head);
    if (!ok?.cur) return;
    const q = new URLSearchParams();
    if (before !== null) q.set('before', String(Number(before)));
    q.set('limit', limit === null ? '50' : String(Number(limit)));
    const r = await ask(ok.node.host, 'GET', `/manage/v1/audit?${q}`, ok.cur.user.name);
    if (!r.ok || r.status !== 200) {
      const f = failure(r, ok.node.host);
      return json(f.status, f.body, f.headers);
    }
    return json(200, { host: ok.node.host, ...cleanAudit(r.body) });
  }

  // GET /api/manage/confirm?host=: the confirm job of a node, or null. It never asks the node.
  function getConfirm(req, searchParams, json, head = false) {
    const a = access(req);
    if (!a.cur) return json(a.status, a.body);
    const node = nodeOf(searchParams.get('host'));
    if (!node) return json(404, NO_NODE);
    if (head) return json(200, {});
    const key = `user:${a.cur.user.name.toLowerCase()}`;
    const wait = confirmReads.wait(key);
    if (wait > 0) return tooOften(json, wait, 'You asked too often how the change is going.');
    confirmReads.take(key);
    return json(200, { host: node.host, job: jobOf(node.host) });
  }

  // Each change: check(body, node) reads only the body and gives what to send, or {error}; then the
  // node is asked, and done(answer body) gives what the page and the audit line get.
  const actions = {
    '/api/manage/settings': {
      op: 'settings',
      expect: 200,
      check(body) {
        const revision = hexOr(body.revision, REVISION_RE);
        if (!revision) return { error: 'The page has no current revision of the settings. Reload the page.' };
        if (!isMap(body.changes)) return { error: 'Send the changes as a map of setting to value.' };
        const entries = Object.entries(body.changes);
        if (entries.length === 0) return { error: 'Nothing to save: no setting was changed.' };
        if (entries.length > MAX_CHANGES) return { error: `At most ${MAX_CHANGES} settings can be changed at once.` };
        for (const [key, value] of entries) {
          if (!KEY_RE.test(key)) return { error: 'A setting name is not valid. Reload the page.' };
          if (typeof value !== 'string') return { error: `The value of ${key} must be text.`, key };
          if (Buffer.byteLength(value) > MAX_VALUE_BYTES) return { error: `The value of ${key} is longer than ${MAX_VALUE_BYTES} bytes.`, key };
        }
        return { send: { revision, changes: Object.fromEntries(entries) }, keys: entries.map(([k]) => k) };
      },
      done(b) {
        const applied = changeList(b.applied);
        return { page: { ok: true, id: hexOr(b.id, CHANGE_ID_RE), applied, notes: listOf(b.notes, 16).map((n) => text(n, MAX_NODE_MESSAGE)).filter(Boolean), settingsRevision: hexOr(b.settings_revision, REVISION_RE) }, keys: applied.map((c) => c.key) };
      },
    },
    '/api/manage/restart': {
      op: 'restart',
      expect: 202,
      check: () => ({ send: {}, keys: [] }),
      done: (b) => ({ page: { ok: true, id: hexOr(b.id, CHANGE_ID_RE), state: 'restarting' }, keys: [] }),
    },
    '/api/manage/rollback': {
      op: 'rollback',
      expect: 200,
      check(body) {
        const id = hexOr(body.id, CHANGE_ID_RE);
        if (!id) return { error: 'There is no change to roll back. Reload the page.' };
        return { send: { id }, keys: [], of: id };
      },
      done(b) {
        const applied = changeList(b.applied);
        return { page: { ok: true, id: hexOr(b.id, CHANGE_ID_RE), applied }, keys: applied.map((c) => c.key) };
      },
    },
    '/api/manage/reticulum': {
      op: 'reticulum',
      expect: 202,
      check(body, node) {
        const revision = hexOr(body.revision, REVISION_RE);
        if (!revision) return { error: 'The page has no current revision of the Reticulum configuration. Reload the page.' };
        if (!Array.isArray(body.changes) || body.changes.length === 0) return { error: 'Nothing to apply: no Reticulum setting was changed.' };
        if (body.changes.length > MAX_RET_CHANGES) return { error: `At most ${MAX_RET_CHANGES} Reticulum settings can be changed at once.` };
        const changes = [];
        for (const c of body.changes) {
          if (!isMap(c)) return { error: 'A change is not valid. Reload the page.' };
          const kind = retPathKind(c.path);
          if (kind === null) return { error: 'A change names a section that cannot be changed from here. Reload the page.' };
          const path = [...c.path];
          const where = `${text(c.key, 32) || 'A setting'} of ${path.join(' / ')}`;
          if (typeof c.key !== 'string' || !Object.hasOwn(RET_EDITS[kind], c.key)) return { error: `${where} cannot be changed from the website.`, path };
          const rule = RET_EDITS[kind][c.key];
          if (!retValueOk(rule, c.value)) return { error: `${where} ${RULE_TEXT[rule]}.`, path, key: c.key };
          if (RET_TURNS_ON.has(c.key) && c.value === 'yes' && enableAllowed.get(node.host) !== true) return { error: `Turning ${where} on is only possible in the terminal on this node.`, path, key: c.key, code: 'enable_not_allowed' };
          if (changes.some((x) => x.key === c.key && samePath(x.path, path))) return { error: `${where} is in the change twice.`, path, key: c.key };
          changes.push({ path, key: c.key, value: c.value });
        }
        return { send: { revision, confirm_seconds: confirmSecondsOf(node.host), changes }, keys: changes.map((c) => [...c.path, c.key].join('/')) };
      },
      done(b) {
        const page = {
          ok: true,
          id: hexOr(b.id, CHANGE_ID_RE),
          state: 'restarting',
          confirmSeconds: whole(b.confirm_seconds, 60, 900),
          applied: changeList(b.applied, MAX_RET_CHANGES),
          notes: listOf(b.notes, 16).map((n) => text(n, MAX_NODE_MESSAGE)).filter(Boolean),
          reticulumRevision: hexOr(b.reticulum_revision, REVISION_RE),
        };
        // The audit line names the keys asked for (the node's applied list is untrusted).
        return { page, keys: [] };
      },
    },
  };

  // POST /api/manage/...
  async function post(req, pathname, json) {
    if (!Object.hasOwn(actions, pathname)) return json(404, { error: 'Not found' });
    const body = await readJsonChange(req, json, 'Send this from the manage page.');
    if (body === null) return;
    const a = access(req);
    if (!a.cur) return json(a.status, a.body);
    const cur = a.cur;
    const actor = cur.user.name;
    if (!recentSignIn(cur.session, now())) return json(403, { error: 'Enter your password again to do this.', reauth: true });
    if (!store.secondFactorEnabled(actor)) return json(403, SECOND_FACTOR_REQUIRED);
    const held = holds.until(actor);
    if (held !== null) return json(403, secondFactorNew(held, now()));
    const action = actions[pathname];
    const node = nodeOf(body.host);
    if (!node) return json(404, NO_NODE);
    const checked = action.check(body, node);
    if (checked.error) return json(400, { error: checked.error, ...(checked.key ? { key: checked.key } : {}), ...(checked.path ? { path: checked.path } : {}), ...(checked.code ? { code: checked.code } : {}) });
    // The node said it takes nothing signed yet: refused before any password or code is asked for.
    const restartLeft = restartWait(node.host);
    if (restartLeft > 0) {
      const f = restartAnswer(restartLeft);
      return json(f.status, f.body, f.headers);
    }
    const key = `user:${actor.toLowerCase()}`;
    const wait = writes.wait(key);
    if (wait > 0) return tooOften(json, wait, 'You made too many changes.');
    writes.take(key);
    // Too many password hashes at once, or a node that is busy, checked or changed nothing: that
    // try is given back.
    const answer = (status, ...rest) => {
      if (status === 503) writes.giveBack(key);
      return json(status, ...rest);
    };
    const ip = clientIp(req, auth.trusted);
    // The session is still there, and the user still has the role (a demoted user's sessions end,
    // but the role is asked again all the same).
    const alive = () => auth.sessions.map.has(cur.id) && allowedRole(store.lookup(actor)?.role);
    const how = await confirmBoth(answer, body, actor, ip, cur);
    if (!how) return;
    if (!alive()) return json(401, GONE);
    // Asked again: a factor reset and set up again while the password was checked starts a wait.
    const heldNow = holds.until(actor);
    if (heldNow !== null) return json(403, secondFactorNew(heldNow, now()));
    const r = await ask(node.host, 'POST', `/manage/v1/${action.op}`, actor, checked.send);
    const line = { actor, host: node.host, ...(checked.of ? { of: checked.of } : {}) };
    if (r.ok && r.status >= 200 && r.status < 300) {
      const d = action.done(isMap(r.body) ? r.body : {});
      // A Reticulum change on probation: the confirm job keeps it once the node can still be reached.
      // Without an id there is nothing to confirm, and the node puts the old config back by itself.
      if (action.op === 'reticulum' && d.page.id && confirmJobs) {
        confirmJobs.start({ host: node.host, id: d.page.id, actor, sessionId: cur.id, confirmSeconds: d.page.confirmSeconds ?? checked.send.confirm_seconds });
        d.page.confirm = jobOf(node.host);
      }
      await audit.write(`manage-${action.op}`, { ...line, keys: d.keys.length === 0 ? checked.keys : d.keys, id: d.page.id, result: 'ok', with: how, address: ip });
      return answer(action.expect, d.page);
    }
    const f = failure(r, node.host, true, action.op);
    await audit.write(`manage-${action.op}`, { ...line, keys: checked.keys, id: null, result: f.code, with: how, address: ip });
    return answer(f.status, f.body, f.headers);
  }

  return { get, getNode, getAudit, getConfirm, post, pageAllowed, nodes: () => [...known.values()] };
}
