// The manage page (/manage), for users with the manage or admin role: pick a node, see its version,
// network and clock, read its Reticulum config, change the few Reticulum settings it allows (tested
// on probation: see manage-confirm.js on the server), change the settings it allows, turn a service
// off, restart Reticulum, roll back the last settings change, and read the node's list of changes.
// Every change is confirmed
// in the step-up dialog (step-up.js) and is a POST of JSON with the X-Rettui-Request header. A user
// without two-step sign-in can look but not change anything; the server says so too.
//
// Everything the node says is untrusted text: it is only ever set with textContent, never as
// markup. The server decides everything; this page only shows what it says.
(function () {
  'use strict';
  var root = document.getElementById('manage');
  if (!root) return;
  var POLL_MS = 3000;
  var POLL_LIMIT_MS = 120000;
  // How long the page follows a confirm job at most; the job itself gives up after 20 minutes.
  var CONFIRM_POLL_LIMIT_MS = 25 * 60000;
  var data = null;
  var node = null;
  var state = null;
  var entries = [];
  // Which node a request is for: an answer for a node no longer shown is dropped.
  var shown = null;
  var poll = null;
  // The inputs of the settings form, by key.
  var inputs = {};
  // The controls of the Reticulum form: [{path, key, rule, was, input, label}].
  var retInputs = [];
  // Following a confirm job: {timer}, or null.
  var retPoll = null;
  // The host the inputs of the settings form belong to, so that edits are only kept for the same node.
  var fieldsHost = null;
  // The Turn off buttons of the settings form, by key: {button, note}.
  var offUi = {};
  // The "Turn off" rows' labels, by key, to give the focus back after the form is built again.
  var offLabels = {};
  // A wait the node asked for before the same button may be pressed again: {key, until, left, text, timer, target, errId, done}.
  var retry = null;
  // What the list of checks shows now, so that it is only built again when it changes.
  var checksKey = null;
  // Whether the node has older entries than the ones loaded.
  var entriesMore = false;

  var VIEW_ONLY_WHY = 'You can look but not change anything yet. See the notice at the top of the page.';
  var RET_VIEW_ONLY_WHY = 'You can look, but not change Reticulum settings yet. See the notice at the top.';

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  // Text that a screen reader reads out as it changes is only written when it is different.
  function put(e, text) { if (e.textContent !== text) e.textContent = text; }
  function say(text) { put($('manage-status'), text); }
  // An error goes in its alert, and is scrolled into view when it is not on the screen.
  function fail(id, text) {
    var e = $(id);
    put(e, text || '');
    if (text && e.scrollIntoView) e.scrollIntoView({ block: 'nearest' });
  }
  function focusOn(e) { if (e && e.focus) e.focus(); }

  function when(seconds) {
    if (typeof seconds !== 'number') return 'unknown';
    var d = new Date(seconds * 1000);
    return isNaN(d.getTime()) ? 'unknown' : d.toLocaleString();
  }

  function read(r) {
    return r.json().catch(function () { return {}; }).then(function (b) { return { status: r.status, body: b || {} }; });
  }

  function fetchJson(path) {
    return fetch(path, { credentials: 'same-origin', cache: 'no-store' }).then(read);
  }

  // A read. A session made with a passkey alone is told to give its password first (403 with reauth:
  // true): the password dialog opens, and the read is sent again once it is given. The answer is the
  // 403 itself when the visitor gives up.
  function getJson(path) {
    return fetchJson(path).then(function (r) {
      if (r.status !== 403 || !r.body.reauth || !window.rettuiStepUp) return r;
      return window.rettuiStepUp.password({ why: 'You signed in with a passkey. Enter your password to see and manage nodes.' }).then(function (a) {
        if (a && a.status === 200) return fetchJson(path);
        return a && a.status === 401 ? a : r;
      });
    });
  }

  function api(path, body) {
    return fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-Rettui-Request': '1' },
      body: JSON.stringify(body || {})
    }).then(read);
  }

  function errorOf(r) {
    return r && r.body && r.body.error ? r.body.error : 'Something went wrong. Try again.';
  }

  // ---- a wait the node asks for ----

  function blocked(key) { return Boolean(retry && retry.key === key); }

  // Shows what is left of the wait beside the button, and keeps the button off. The words are
  // for the eyes only (aria-hidden): the refusal itself was read out once.
  function drawRetry() {
    if (!retry) return;
    var t = retry.target();
    if (!t) return;
    t.button.disabled = true;
    var text = 'You can try again in ' + (retry.left > 120 ? Math.ceil(retry.left / 60) + ' min' : retry.left + ' s') + '.';
    put(t.note, text);
  }

  function endRetry(announce) {
    var me = retry;
    if (!me) return;
    window.clearTimeout(me.timer);
    retry = null;
    var t = me.target();
    if (t) put(t.note, '');
    me.done();
    // A button that was off has lost the focus: it comes back when the button works again.
    if (t && document.activeElement === document.body) focusOn(t.button);
    if (announce) {
      fail(me.errId, '');
      say('You can try again now.');
    }
  }

  // After a refusal that says how long to wait (retryAfter, with 429 or 503): the pressed button stays
  // off until then, with the time left beside it. One wait at a time. target() gives {button, note}.
  function startRetry(r, key, errId, target, done) {
    var secs = r && r.body && typeof r.body.retryAfter === 'number' && isFinite(r.body.retryAfter) ? Math.ceil(r.body.retryAfter) : 0;
    if (secs <= 0 || (r.status !== 429 && r.status !== 503)) return false;
    endRetry(false);
    secs = Math.min(secs, 3600);
    var me = { key: key, until: Date.now() + secs * 1000, left: secs, timer: null, target: target, errId: errId, done: done };
    retry = me;
    drawRetry();
    (function next() {
      me.timer = window.setTimeout(function () {
        if (retry !== me) return;
        // Counts down by at least one a second, and follows the clock when a busy tab was late.
        me.left = Math.min(me.left - 1, Math.ceil((me.until - Date.now()) / 1000));
        if (me.left <= 0) { endRetry(true); return; }
        drawRetry();
        next();
      }, 1000);
    })();
    return true;
  }

  // Whether the wait after a first second factor runs: the server sends when it ends.
  var waiting = function () { return Boolean(data && typeof data.nodeChangesFrom === 'string' && Date.parse(data.nodeChangesFrom) > Date.now()); };
  var canChange = function () { return Boolean(data && data.secondFactor) && !waiting(); };

  // A change confirmed in the step-up dialog. When the sign in is older than 15 minutes, the
  // password just given makes it recent again and the change is sent again. Gives the answer, or
  // null when the user gave up or must sign in again.
  function confirmed(path, body, opts) {
    if (!window.rettuiStepUp) return Promise.resolve({ status: 0, body: { error: 'The page did not load completely. Reload it.' } });
    return window.rettuiStepUp.ask({
      title: opts.title,
      why: opts.why,
      action: opts.action,
      danger: opts.danger,
      // For a change that turns something on: what it opens, and the box to tick (step-up.js).
      opens: opts.opens,
      acknowledge: opts.acknowledge,
      secondFactor: Boolean(data && data.secondFactor),
      methods: data && Array.isArray(data.stepUpMethods) ? data.stepUpMethods : undefined,
      send: function (fields) {
        var full = {};
        Object.keys(body).forEach(function (k) { full[k] = body[k]; });
        Object.keys(fields).forEach(function (k) { full[k] = fields[k]; });
        return api(path, full).then(function (r) {
          if (r.status !== 403 || !r.body.reauth) return r;
          return api('/api/account/reauth', { password: fields.password }).then(function (a) {
            return a.status === 200 ? api(path, full) : a;
          });
        });
      }
    }).then(function (r) {
      if (r && r.status === 401 && r.body.signIn) {
        load();
        return null;
      }
      return r;
    });
  }

  // ---- the node's state ----

  var ON = ['true', 'yes', 'on', '1'];
  function isOn(value) { return ON.indexOf(String(value).toLowerCase()) >= 0; }

  var SECTIONS = [['pn_', 'Propagation node'], ['node_', 'Node'], ['hub_', 'Hub'], ['git_host_', 'Git host']];
  function sectionOf(s) {
    if (s.section) return s.section;
    for (var i = 0; i < SECTIONS.length; i++) if (s.key.indexOf(SECTIONS[i][0]) === 0) return SECTIONS[i][1];
    return 'General';
  }

  function statusLine(s) {
    var parts = [];
    if (s.version) parts.push('rettui ' + s.version);
    var n = s.network || {};
    var net = n.state === 'running' ? 'Reticulum running' : n.state === 'starting' ? 'Reticulum starting' : n.state === 'failed' ? 'Reticulum failed' : 'Reticulum state unknown';
    if (typeof n.interfaces_total === 'number' && typeof n.interfaces_online === 'number') net += ', ' + n.interfaces_online + ' of ' + n.interfaces_total + ' interfaces online';
    if (n.shared_instance) net += ', shared instance';
    parts.push(net);
    if (typeof s.skewSeconds === 'number') {
      var off = Math.abs(s.skewSeconds);
      parts.push(off < 60 ? 'clock in step' : 'clock ' + Math.round(off / 60) + ' min off');
    }
    return parts.join(' · ');
  }

  function restartText(r) {
    if (!r) return '';
    if (r.state === 'restarting') return 'Reticulum is restarting (since ' + when(r.started) + ').';
    if (r.state === 'up') return 'The last restart (' + when(r.started) + ') went well: every interface is back.';
    if (r.state === 'unhealthy') return 'After the last restart (' + when(r.started) + ') not everything came back' + (r.problems && r.problems.length ? ': ' + r.problems.join('; ') : '') + '.';
    return '';
  }

  // The sections of the page, and the entry of each in the list of links.
  var NAV = ['manage-settings', 'manage-ret', 'manage-ret-edit', 'manage-restart-card', 'manage-last-card', 'manage-audit-card'];

  // The list of links lists only the sections that are there.
  function syncNav() {
    var any = false;
    NAV.forEach(function (id) {
      var gone = Boolean($(id).hidden);
      $('nav-' + id).hidden = gone;
      if (!gone) any = true;
    });
    $('manage-nav').hidden = !any;
  }

  // The edits in the forms, to put back when the forms are built again for the same node:
  // {settings: {key: {value, was}}, ret: {id: {value, was}}}.
  function takeEdits() {
    if (!state || !node || fieldsHost !== node.host) return null;
    var out = { settings: {}, ret: {} };
    (state.settings || []).forEach(function (s) {
      if (s.access !== 'change' || !Object.prototype.hasOwnProperty.call(inputs, s.key)) return;
      var input = inputs[s.key];
      var now = s.kind === 'toggle' ? (input.checked ? 'true' : 'false') : input.value;
      var was = s.kind === 'toggle' ? (isOn(s.value) ? 'true' : 'false') : s.value;
      if (now !== was) out.settings[s.key] = { value: now, was: was };
    });
    retInputs.forEach(function (x) {
      var v = String(x.input.value);
      if (v !== x.shown) out.ret[retId(x)] = { value: v, was: x.was };
    });
    return out;
  }

  function restartWhy() {
    if (!canChange()) return VIEW_ONLY_WHY;
    if ((state.restart && state.restart.state === 'restarting') || poll !== null) return 'Reticulum is restarting. Restart is possible again when it is back.';
    if (state.pending) return 'A Reticulum change is being tested. Restart waits until it is kept or put back.';
    if (typeof state.restart_allowed_at === 'number' && state.restart_allowed_at * 1000 > Date.now()) return 'The node allows the next restart at ' + when(state.restart_allowed_at) + '.';
    return '';
  }

  function paintRestart() {
    var why = restartWhy();
    $('manage-restart').disabled = Boolean(why) || blocked('restart');
    $('manage-restart').setAttribute('aria-describedby', 'manage-restart-why');
    put($('manage-restart-why'), why);
    $('manage-restart-why').hidden = !why;
  }

  function paintState(edits) {
    put($('manage-node-h'), node.name === node.host ? node.host : node.name + ' (' + node.host + ')');
    put($('manage-line'), statusLine(state));
    var warn = (state.clock && state.clock.warning) || '';
    if ($('manage-clock').hidden !== !warn) $('manage-clock').hidden = !warn;
    put($('manage-clock'), warn);
    var rt = restartText(state.restart);
    $('manage-restart-state').hidden = !rt;
    put($('manage-restart-state'), rt);
    $('manage-revision').value = state.settings_revision || '';
    paintFields(edits && edits.settings);
    paintReticulum();
    paintRetEdit(edits && edits.ret);
    paintRestart();
    fail('manage-restart-error', '');
    $('manage-settings').hidden = false;
    $('manage-restart-card').hidden = false;
    syncNav();
  }

  // One input per setting the node may change, grouped in fieldsets; a service that can only be
  // turned off is a button instead.
  function paintFields(edits) {
    var box = $('manage-fields');
    box.textContent = '';
    inputs = {};
    offUi = {};
    offLabels = {};
    fieldsHost = node.host;
    var groups = {};
    var order = [];
    (state.settings || []).forEach(function (s) {
      var name = sectionOf(s);
      if (!groups[name]) { groups[name] = []; order.push(name); }
      groups[name].push(s);
    });
    if (order.length === 0) box.appendChild(el('p', 'note', 'This node offers no settings to change.'));
    order.forEach(function (name, g) {
      var fs = el('fieldset', 'users-choice manage-group');
      fs.appendChild(el('legend', null, name));
      groups[name].forEach(function (s, i) { fs.appendChild(field(s, 'mf-' + g + '-' + i)); });
      box.appendChild(fs);
    });
    // An edit stays when the node's value of that setting is still the one it was made from.
    (state.settings || []).forEach(function (s) {
      var e = edits && edits[s.key];
      var input = inputs[s.key];
      if (!e || !input) return;
      var was = s.kind === 'toggle' ? (isOn(s.value) ? 'true' : 'false') : s.value;
      if (was !== e.was) return;
      if (s.kind === 'toggle') input.checked = e.value === 'true';
      else input.value = e.value;
    });
    var some = (state.settings || []).some(function (s) { return s.access === 'change'; });
    $('manage-save').disabled = !canChange() || !some || blocked('save');
    var why = !canChange() ? VIEW_ONLY_WHY : !some ? 'This node does not let the website change any of these settings.' : '';
    put($('manage-why'), why);
    $('manage-why').hidden = !why;
    paintDirty();
    drawRetry();
  }

  // How many settings of the form differ from the node's.
  function paintDirty() {
    var n = state ? changes().labels.length : 0;
    put($('manage-form-dirty'), n === 0 ? 'No changes.' : n + (n === 1 ? ' setting' : ' settings') + ' changed, not saved yet.');
  }

  function field(s, id) {
    var row = el('div', 'manage-field');
    var helpId = id + '-help';
    var help = s.help ? el('p', 'note', s.help) : null;
    if (help) help.id = helpId;
    if (s.access === 'turn_off_only') {
      var on = isOn(s.value);
      var stateLine = el('p', 'manage-label', s.label + ': ' + (on ? 'on' : 'off'));
      // Something for the focus to go to when this row is built again after Turn off.
      stateLine.setAttribute('tabindex', '-1');
      offLabels[s.key] = stateLine;
      row.appendChild(stateLine);
      if (help) row.appendChild(help);
      var b = el('button', 'danger', 'Turn off');
      b.type = 'button';
      b.setAttribute('aria-label', 'Turn off ' + s.label);
      b.setAttribute('aria-describedby', (help ? helpId + ' ' : '') + 'manage-why');
      b.disabled = !on || !canChange() || blocked('off:' + s.key);
      b.addEventListener('click', function () { turnOff(s); });
      var actions = el('div', 'login-actions');
      actions.appendChild(b);
      var note = el('span', 'manage-retry');
      note.setAttribute('aria-hidden', 'true');
      actions.appendChild(note);
      offUi[s.key] = { button: b, note: note };
      row.appendChild(actions);
      if (!on) row.appendChild(el('p', 'note', 'Turn on in the terminal on the node.'));
      return row;
    }
    var input;
    if (s.kind === 'toggle') {
      row.className = 'manage-field users-radio';
      input = el('input');
      input.type = 'checkbox';
      input.checked = isOn(s.value);
    } else if (s.kind === 'choice') {
      input = el('select');
      var choices = (s.choices || []).slice();
      if (choices.indexOf(s.value) < 0) choices.unshift(s.value);
      choices.forEach(function (c) {
        var o = el('option', null, c === '' ? '(none)' : c);
        o.value = c;
        input.appendChild(o);
      });
      input.value = s.value;
    } else {
      input = el('input');
      input.type = 'text';
      input.maxLength = 4096;
      input.autocomplete = 'off';
      input.spellcheck = false;
      ['data-bwignore', 'data-1p-ignore', 'data-lpignore'].forEach(function (a) { input.setAttribute(a, 'true'); });
      if (s.kind === 'number') input.setAttribute('inputmode', 'numeric');
      input.value = s.value;
    }
    input.id = id;
    inputs[s.key] = input;
    input.addEventListener('input', paintDirty);
    input.addEventListener('change', paintDirty);
    input.setAttribute('aria-describedby', (help ? helpId + ' ' : '') + 'manage-form-error');
    // A node that already says it in its label does not get the words twice.
    var label = el('label', null, s.label + (s.kind === 'optional' && !/\(may be empty\)$/.test(s.label) ? ' (may be empty)' : ''));
    label.htmlFor = id;
    if (s.kind === 'toggle') { row.appendChild(input); row.appendChild(label); }
    else { row.appendChild(label); row.appendChild(input); }
    if (help) row.appendChild(help);
    return row;
  }

  // The settings whose value on the page differs from what the node said.
  function changes() {
    var out = {};
    var list = [];
    var said = [];
    (state.settings || []).forEach(function (s) {
      if (s.access !== 'change' || !Object.prototype.hasOwnProperty.call(inputs, s.key)) return;
      var input = inputs[s.key];
      var now = s.kind === 'toggle' ? (input.checked ? 'true' : 'false') : input.value;
      var was = s.kind === 'toggle' ? (isOn(s.value) ? 'true' : 'false') : s.value;
      if (now === was) return;
      out[s.key] = now;
      list.push(s.label);
      // The dialog says what each setting becomes, with a long value cut.
      var shown = s.kind === 'toggle' ? (now === 'true' ? 'on' : 'off') : now.length > 60 ? now.slice(0, 60) + '...' : now;
      said.push(s.label + ' to "' + shown + '"');
    });
    return { map: out, labels: list, said: said };
  }

  // ---- the node's Reticulum config, read only ----

  function retValue(k) {
    if (k.value === null || k.value === undefined) return k.set ? 'set (hidden)' : 'not set';
    return k.value === '' ? '(empty)' : String(k.value);
  }

  function paintReticulum() {
    var r = state && state.reticulum;
    var box = $('manage-ret-sections');
    box.textContent = '';
    $('manage-ret').hidden = false;
    $('manage-ret-shared').hidden = !(r && r.shared_instance === true);
    if (!r || !Array.isArray(r.sections)) {
      put($('manage-ret-status'), 'This node does not say what its Reticulum config holds.');
      return;
    }
    var said = [];
    if (r.sections.length === 0) said.push('The node lists no Reticulum configuration.');
    if (r.truncated === true) said.push('Part of the config is not shown.');
    put($('manage-ret-status'), said.join(' '));
    r.sections.forEach(function (sec) {
      var path = Array.isArray(sec.path) ? sec.path : [];
      var keys = Array.isArray(sec.keys) ? sec.keys : [];
      var title = path.join(' / ');
      var group = el('div', 'manage-ret-section');
      group.appendChild(el('h3', null, title));
      if (keys.length === 0) { group.appendChild(el('p', 'note', 'No settings listed.')); box.appendChild(group); return; }
      var table = el('table', 'users-table manage-ret-table');
      table.appendChild(el('caption', 'sr-only', 'Reticulum settings of ' + title));
      var head = el('tr');
      ['Setting', 'Value'].forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; head.appendChild(th); });
      var thead = el('thead');
      thead.appendChild(head);
      table.appendChild(thead);
      var body = el('tbody');
      keys.forEach(function (k) {
        var tr = el('tr');
        var th = el('th', null, String(k.key));
        th.scope = 'row';
        tr.appendChild(th);
        cell(tr, 'Value', retValue(k));
        body.appendChild(tr);
      });
      table.appendChild(body);
      group.appendChild(table);
      box.appendChild(group);
    });
  }

  // ---- changing the node's Reticulum config, on probation ----

  var SWITCH_ON = ['yes', 'true', 'on', '1'];
  var SWITCH_OFF = ['no', 'false', 'off', '0'];
  var MODES = ['full', 'gateway', 'access_point', 'roaming', 'boundary'];
  // The settings the node lets the website change, per kind of section: the key that is sent, the
  // names it may have in the file, and how it is shown.
  var RET_RETICULUM = [
    { key: 'enable_transport', names: ['enable_transport'], rule: 'switch', label: 'Transport (enable_transport)', help: 'Whether this node passes traffic and announces on for other peers.' }
  ];
  var RET_INTERFACE = [
    { key: 'enabled', names: ['enabled', 'interface_enabled'], rule: 'switch', label: 'Enabled', help: 'Whether Reticulum starts this interface. Turning on a server interface opens its port.' },
    { key: 'mode', names: ['mode', 'interface_mode'], rule: 'mode', label: 'Mode', help: 'How the interface passes announces and paths on.' },
    { key: 'announce_cap', names: ['announce_cap'], rule: 'number', label: 'Announce cap (percent)', help: 'The share of the bitrate announces may use: above 0, at most 100.' },
    { key: 'bitrate', names: ['bitrate'], rule: 'number', label: 'Bitrate (bits per second)', help: 'The speed Reticulum assumes for this interface: 5 to 10000000000.' },
    { key: 'ingress_control', names: ['ingress_control'], rule: 'switch', label: 'Ingress control', help: 'Holds back the announces of new peers that come in all at once.' }
  ];

  // What turning a setting on opens up, in the website's own words; the node says more once the
  // change is made (its notes).
  var OPENS = {
    enable_transport: 'Transport: this node passes traffic and announces on for other peers, and is known on the network as a transport node.',
    enabled: 'The interface starts: a server interface opens its listening port (on every address when it listens on 0.0.0.0), a client interface connects out, and this node is announced on it.'
  };
  var ENABLE_ONLY_TERMINAL = 'Turning this on is only possible in the terminal on this node.';

  // Whether the node lets the website turn an interface or transport on.
  function enableAllowed() { return Boolean(state && state.reticulum_enable_allowed === true); }

  function samePath(a, b) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  // The value of a setting in a section of the view: the first of its names that is set, or null.
  function currentOf(sec, names) {
    var keys = Array.isArray(sec.keys) ? sec.keys : [];
    for (var n = 0; n < names.length; n++) {
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (String(k.key).toLowerCase() === names[n] && k.set && typeof k.value === 'string') return k.value;
      }
    }
    return null;
  }

  function switchOf(v) {
    var x = String(v).toLowerCase();
    return SWITCH_ON.indexOf(x) >= 0 ? 'yes' : SWITCH_OFF.indexOf(x) >= 0 ? 'no' : null;
  }

  // How long the node waits for the website, in words.
  function windowText(seconds) {
    var s = typeof seconds === 'number' && seconds > 0 ? seconds : 300;
    if (s % 60 === 0) return s / 60 + (s === 60 ? ' minute' : ' minutes');
    return s + ' seconds';
  }

  function applyText() {
    return 'Reticulum restarts. The website then checks that it can still reach this node and keeps the change. If it can\'t within ' + windowText(state && state.confirmSeconds) + ', the node puts the old config back by itself.';
  }

  // A time of the node, as hours and minutes.
  function clock(seconds) {
    if (typeof seconds !== 'number') return 'unknown';
    var d = new Date(seconds * 1000);
    return isNaN(d.getTime()) ? 'unknown' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function jobRunning(job) {
    return Boolean(job && job.state !== 'done' && job.state !== 'gave-up');
  }

  function changeWords(list) {
    return (list || []).map(function (c) { return (Array.isArray(c.path) ? c.path.join(' / ') + ' / ' : '') + c.key + ' to "' + c.to + '"'; }).join(', ');
  }

  // What the node says about a pending change, the confirm job and the last change, in words.
  function retStatusText() {
    var p = state.pending;
    var job = state.confirm || null;
    var res = state.reticulum_result;
    if (p) {
      var what = p.changes && p.changes.length ? ' (' + changeWords(p.changes) + (p.actor ? ', by ' + p.actor : '') + ')' : '';
      if (p.state === 'restarting') return 'Restarting: Reticulum is restarting with the change' + what + '.';
      if (p.state === 'probation') {
        var mine = job && job.id === p.id ? job.message : 'The website is not checking this change, so the node puts the old config back then.';
        return 'On probation until ' + clock(p.confirm_by) + what + '. ' + mine;
      }
      if (p.state === 'rolling_back') return 'Rolling back: the node is putting the old config back' + what + (p.problems && p.problems.length ? ', as ' + p.problems.join('; ') : '') + '.';
      return 'A Reticulum change is pending on this node' + what + '.';
    }
    if (job && job.state === 'gave-up') return job.message;
    if (res) {
      var why = res.message ? ': ' + res.message : '.';
      if (res.outcome === 'committed') return 'Kept: the last Reticulum change (' + when(res.at) + ') passed the test.';
      if (res.outcome === 'rolled_back') return 'Rolled back: the node put the old config back' + why;
      if (res.outcome === 'rollback_failed') return 'Not rolled back: the node could not put the old config back' + why + ' Check the node in the terminal.';
      if (res.outcome === 'left') return 'Left as it was: the config was changed on the node meanwhile' + why;
    }
    if (job && job.state === 'done') return job.message;
    return '';
  }

  // What the node's own check of one interface says, in words.
  var CHECK_TEXT = {
    self_test: { waiting: 'waiting for a test answer', passed: 'Reticulum answered a test request', failed: 'Reticulum did not answer a test request' },
    online: { waiting: 'waiting to come online', traffic: 'online, traffic seen', no_traffic: 'online, no traffic yet', failed: 'not online' }
  };

  // The node's checks of the pending change, one line per interface and kind, while it is pending.
  // The list is in a live region: it is built again only when its words change.
  function paintChecks() {
    var list = $('manage-ret-checks');
    var checks = state.pending && Array.isArray(state.pending.checks) ? state.pending.checks : [];
    var lines = [];
    checks.forEach(function (c) {
      var words = CHECK_TEXT[c.kind] && CHECK_TEXT[c.kind][c.result];
      if (words) lines.push({ c: c, words: words });
    });
    var key = lines.map(function (l) { return String(l.c.interface) + ': ' + l.words; }).join('\n');
    if (key !== checksKey || list.hidden !== (lines.length === 0)) {
      checksKey = key;
      list.textContent = '';
      lines.forEach(function (l) {
        var c = l.c;
        var words = l.words;
        list.appendChild(el('li', null, String(c.interface) + ': ' + words));
      });
      list.hidden = list.children.length === 0;
    }
  }

  // What is left of the probation, in words, for the eyes only (it is not in the live region).
  function leftText(p) {
    if (!p || p.state !== 'probation' || typeof p.confirm_by !== 'number') return '';
    var secs = Math.round(p.confirm_by - Date.now() / 1000);
    if (secs <= 0) return 'The time is up. The node is finishing the test.';
    if (secs < 60) return 'Less than a minute left.';
    var m = Math.ceil(secs / 60);
    return 'About ' + m + (m === 1 ? ' minute' : ' minutes') + ' left.';
  }

  // The status of a Reticulum change: in the live region of its section, and as one line in the node
  // card at the top. Every write is only made when the text changes.
  function paintRetStatus() {
    var status = retStatusText();
    var pendingEl = $('manage-ret-pending');
    if (pendingEl.textContent !== status) $('manage-ret-pending').textContent = status;
    paintChecks();
    var p = state.pending;
    put($('manage-pending-text'), p ? status : '');
    $('manage-pending-line').hidden = !p;
    // The countdown runs while the page follows the job, which asks again every 3 seconds.
    var left = retPoll ? leftText(p) : '';
    put($('manage-ret-left'), left);
    $('manage-ret-left').hidden = !left;
    var mine = p && state.confirm && state.confirm.id === p.id && jobRunning(state.confirm);
    var auto = !p ? '' : mine
      ? 'The website is testing the change. Nothing to click: it is kept if the test passes, and put back by the node if not.'
      : 'Nothing to click here: the node puts the old config back by itself if the change is not kept in time.';
    put($('manage-ret-auto'), auto);
    $('manage-ret-auto').hidden = !auto;
    var cls = 'acct-card' + (p && p.state === 'probation' ? ' on-probation' : '');
    if ($('manage-ret-edit').className !== cls) $('manage-ret-edit').className = cls;
  }

  // The Reticulum form: one fieldset per section the node lets the website change. It is there only
  // for a user who may change things, on a node without a shared instance, while nothing is pending.
  function paintRetEdit(edits) {
    var r = state.reticulum;
    var editable = r && Array.isArray(r.editable) ? r.editable : [];
    var shared = Boolean((r && r.shared_instance) || (state.network && state.network.shared_instance));
    var busy = Boolean(state.pending) || jobRunning(state.confirm);
    var open = canChange() && !shared && editable.length > 0 && !busy;
    var status = retStatusText();
    // When there is no form, one line says why, instead of the section just being gone.
    var why = !(r && Array.isArray(r.sections)) ? '' : !canChange() ? RET_VIEW_ONLY_WHY : shared ? 'This node uses a shared Reticulum instance, so the website does not change its settings.' : editable.length === 0 ? 'This node does not let the website change any Reticulum settings.' : '';
    $('manage-ret-edit').hidden = !open && !status && !why;
    $('manage-ret-form').hidden = !open;
    $('manage-ret-lead').hidden = !open;
    put($('manage-ret-why'), why);
    $('manage-ret-why').hidden = !why;
    paintRetStatus();
    put($('manage-ret-apply-help'), applyText());
    $('manage-ret-revision').value = (r && r.revision) || '';
    var box = $('manage-ret-fields');
    box.textContent = '';
    retInputs = [];
    paintRetDirty();
    if (!open) return;
    editable.forEach(function (path, g) {
      var sec = null;
      r.sections.forEach(function (x) { if (samePath(x.path, path)) sec = x; });
      if (!sec) return;
      var fs = el('fieldset', 'users-choice manage-group');
      fs.appendChild(el('legend', null, path.join(' / ')));
      (path[0] === 'reticulum' ? RET_RETICULUM : RET_INTERFACE).forEach(function (spec, i) {
        fs.appendChild(retField(path, sec, spec, 'mr-' + g + '-' + i));
      });
      box.appendChild(fs);
    });
    // An edit stays when the node's value is still the one it was made from.
    retInputs.forEach(function (x) {
      var e = edits && edits[retId(x)];
      if (e && e.was === x.was) x.input.value = e.value;
    });
    paintRetDirty();
    drawRetry();
  }

  function option(select, value, text) {
    var o = el('option', null, text);
    o.value = value;
    select.appendChild(o);
  }

  function retId(x) { return x.path.join(' / ') + ' / ' + x.key; }

  function retField(path, sec, spec, id) {
    var row = el('div', 'manage-field');
    var was = currentOf(sec, spec.names);
    var input;
    var locked = false;
    var leave = false;
    var isSelect = spec.rule === 'switch' || spec.rule === 'mode';
    if (isSelect) {
      input = el('select');
      var now = spec.rule === 'switch' ? switchOf(was) : (was !== null && MODES.indexOf(was.toLowerCase()) >= 0 ? was.toLowerCase() : null);
      // A value that is not set, or not one of the choices, stays as it is unless one is picked.
      leave = now === null;
      if (leave) option(input, '', was === null ? '(not set, leave as is)' : '(now: ' + was + ', leave as is)');
      var choices = spec.rule === 'switch' ? ['yes', 'no'] : MODES;
      // Turning on, where the node does not allow it from here: only off (or as it is) is offered.
      if (OPENS[spec.key] && !enableAllowed() && now !== 'yes') {
        choices = ['no'];
        locked = true;
      }
      choices.forEach(function (c) { option(input, c, c); });
      input.value = now === null ? '' : now;
    } else {
      input = el('input');
      input.type = 'text';
      input.maxLength = 32;
      input.autocomplete = 'off';
      input.spellcheck = false;
      ['data-bwignore', 'data-1p-ignore', 'data-lpignore'].forEach(function (a) { input.setAttribute(a, 'true'); });
      input.setAttribute('inputmode', spec.key === 'bitrate' ? 'numeric' : 'decimal');
      input.value = was === null ? '' : was;
    }
    input.id = id;
    var helpId = id + '-help';
    input.setAttribute('aria-describedby', helpId + ' manage-ret-error');
    var label = el('label', null, spec.label);
    label.htmlFor = id;
    var extra = leave ? ' Pick a value to change it. Leave this to keep it as it is.' : !isSelect && was === null ? ' Not set now.' : '';
    var help = el('p', 'note', spec.help + extra + (locked ? ' ' + ENABLE_ONLY_TERMINAL : ''));
    help.id = helpId;
    // What the node has now, shown once the value is changed (text, not only a colour).
    var wasLine = el('p', 'note manage-was', '');
    wasLine.hidden = true;
    row.appendChild(label);
    row.appendChild(wasLine);
    row.appendChild(input);
    row.appendChild(help);
    var x = { path: path, key: spec.key, rule: spec.rule, was: was, input: input, label: path.join(' / ') + ' / ' + spec.label, shown: input.value, row: row, wasLine: wasLine };
    retInputs.push(x);
    input.addEventListener('input', paintRetDirty);
    input.addEventListener('change', paintRetDirty);
    return row;
  }

  // How one control stands against the node's value: 'same', 'changed', or 'blank' (a number
  // that is set cannot be taken away from here).
  function retStand(x) {
    var now = String(x.input.value).trim();
    if (now === '') return { kind: x.rule === 'number' && x.was !== null ? 'blank' : 'same', now: now };
    var was = x.was === null ? null : x.rule === 'switch' ? switchOf(x.was) : x.rule === 'mode' ? x.was.toLowerCase() : x.was;
    if (was !== null && (now === was || (x.rule === 'number' && Number(now) === Number(was)))) return { kind: 'same', now: now };
    return { kind: 'changed', now: now };
  }

  // Marks the controls that differ from the node's value, with the old value in words, and counts them.
  function paintRetDirty() {
    var n = 0;
    retInputs.forEach(function (x) {
      var changed = retStand(x).kind === 'changed';
      if (changed) n++;
      var cls = changed ? 'manage-field changed' : 'manage-field';
      if (x.row.className !== cls) x.row.className = cls;
      x.wasLine.hidden = !changed;
      if (changed) put(x.wasLine, 'Was: ' + (x.was === null ? 'not set' : x.was));
    });
    put($('manage-ret-dirty'), n === 0 ? 'No changes.' : n + (n === 1 ? ' change' : ' changes') + ' not applied yet.');
  }

  // The settings whose value on the page differs from the node's: {list, labels}, or {error}.
  function retChanges() {
    var list = [];
    var labels = [];
    // What the change turns on, and so opens up.
    var opens = [];
    for (var i = 0; i < retInputs.length; i++) {
      var x = retInputs[i];
      var st = retStand(x);
      var now = st.now;
      if (st.kind === 'blank') return { error: x.label + ': a value can be changed here, but not removed. Remove it in the terminal.' };
      if (st.kind === 'same') continue;
      list.push({ path: x.path, key: x.key, value: now });
      labels.push(x.label + ' to ' + now);
      if (OPENS[x.key] && now === 'yes') opens.push(x.path.join(' / ') + ': ' + OPENS[x.key]);
    }
    return { list: list, labels: labels, opens: opens };
  }

  function applyTarget() { return { button: $('manage-ret-apply'), note: $('manage-ret-apply-retry') }; }

  $('manage-ret-form').addEventListener('submit', function (e) {
    e.preventDefault();
    if (!state || !canChange()) return;
    var c = retChanges();
    if (c.error) { fail('manage-ret-error', c.error); return; }
    if (c.list.length === 0) { fail('manage-ret-error', 'Nothing to apply: no Reticulum setting was changed.'); return; }
    fail('manage-ret-error', '');
    var host = node.host;
    var go = $('manage-ret-apply');
    go.disabled = true;
    var moved = false;
    var ask = {
      title: 'Apply and test on ' + node.name,
      why: applyText() + ' Changes ' + c.labels.join(', ') + '.',
      action: 'Apply and test',
      danger: true
    };
    // Turning something on: the dialog lists what it opens, and asks for a tick before it applies.
    if (c.opens.length) {
      ask.why += ' This turns on what is listed below.';
      ask.opens = c.opens;
      ask.acknowledge = 'I know what this opens on the node, and want it.';
    }
    confirmed('/api/manage/reticulum', { host: host, revision: $('manage-ret-revision').value, changes: c.list }, ask).then(function (r) {
      if (shown !== host || !r) return;
      if (r.status === 202) {
        fail('manage-ret-error', '');
        // Shown as restarting until the job says more; the form is gone until it is over.
        state.pending = { id: r.body.id, state: 'restarting', changes: r.body.applied || [], problems: [] };
        state.confirm = r.body.confirm || null;
        paintRetEdit();
        paintRestart();
        syncNav();
        moved = true;
        // The form is gone: the focus goes to the heading, where the status is.
        focusOn($('manage-ret-edit-h'));
        // The node's own words of what the change opens, now that it is made.
        var notes = Array.isArray(r.body.notes) && r.body.notes.length ? ' The node says: ' + r.body.notes.join(' ') : '';
        say('Reticulum is restarting with the change. This page shows how the test goes.' + notes);
        if (r.body.confirm) startRetPoll(host);
        return;
      }
      fail('manage-ret-error', errorOf(r));
      startRetry(r, 'apply', 'manage-ret-error', applyTarget, function () { go.disabled = false; });
      if (r.body && (r.body.code === 'stale_revision' || r.body.code === 'pending' || r.body.code === 'unknown_section')) return loadNode('The Reticulum configuration was loaded again.', true);
    }).catch(function () { fail('manage-ret-error', 'Could not reach the server. Try again.'); })
      .then(function () {
        go.disabled = blocked('apply');
        // The dialog closed on a button that was off: the focus comes back to it.
        if (!moved && !go.disabled) focusOn(go);
      });
  });

  // What the job says moves the pending change on, as the node would show it: on probation (with its
  // deadline) once the job probes, confirms or knows the deadline, or as the node last said.
  function followJob(job) {
    var p = state.pending;
    if (!p || p.id !== job.id) return;
    var known = job.nodeState === 'restarting' || job.nodeState === 'probation' || job.nodeState === 'rolling_back';
    var next = known ? job.nodeState : (job.state === 'probing' || job.state === 'confirming' || typeof job.confirmBy === 'number') ? 'probation' : p.state;
    if (next === 'probation' && typeof job.confirmBy === 'number') p.confirm_by = job.confirmBy;
    p.state = next;
    // The node's own checks, as the job last read them.
    if (Array.isArray(job.checks)) p.checks = job.checks;
  }

  function stopRetPoll() {
    if (retPoll) window.clearTimeout(retPoll.timer);
    retPoll = null;
  }

  // Asks the server every 3 seconds how the confirm job goes, while it runs; then loads the node
  // once, to show how it ended.
  function startRetPoll(host) {
    stopRetPoll();
    var started = Date.now();
    retPoll = { timer: null };
    var me = retPoll;
    function next() {
      me.timer = window.setTimeout(function () {
        if (retPoll !== me || shown !== host) return;
        getJson('/api/manage/confirm?host=' + encodeURIComponent(host)).then(function (r) {
          if (retPoll !== me || shown !== host) return;
          if (r.status === 429) { retPoll = null; say('The page stopped asking how the change goes, as it asked too often. Reload the page in a while.'); return; }
          var job = r.status === 200 ? r.body.job : undefined;
          if (r.status === 200 && !jobRunning(job)) {
            retPoll = null;
            state.confirm = job || null;
            return loadNode(job ? job.message : '');
          }
          if (job) {
            state.confirm = job;
            followJob(job);
            paintRetStatus();
          }
          if (Date.now() - started >= CONFIRM_POLL_LIMIT_MS) { retPoll = null; say('The page stopped asking how the change goes. Reload the page to check the node.'); return; }
          next();
        }, function () {
          if (retPoll !== me) return;
          if (Date.now() - started >= CONFIRM_POLL_LIMIT_MS) { retPoll = null; say('Could not reach the server. Reload the page to check the node.'); return; }
          next();
        });
      }, POLL_MS);
    }
    next();
  }

  // ---- the node's list of changes ----

  var OPS = { settings: 'Settings', restart: 'Restart', rollback: 'Roll back', reticulum: 'Reticulum config', confirm: 'Confirm', auto_rollback: 'Rolled back by itself', auth_failures: 'Refused requests' };
  var RESULTS = { ok: 'Done', refused: 'Refused', failed: 'Failed', rolled_back: 'Rolled back' };

  function changesText(list) {
    if (!list || list.length === 0) return '-';
    return list.map(function (c) { return (Array.isArray(c.path) ? c.path.join(' / ') + ' / ' : '') + c.key + ': "' + c.from + '" to "' + c.to + '"'; }).join('; ');
  }

  function cell(row, label, text, cls) {
    var td = el('td', cls || null, text);
    td.setAttribute('data-label', label);
    row.appendChild(td);
  }

  // A shorter date for the list of changes, in the person's own language and time zone.
  function whenShort(seconds) {
    if (typeof seconds !== 'number') return 'unknown';
    var d = new Date(seconds * 1000);
    return isNaN(d.getTime()) ? 'unknown' : d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  }

  function paintAudit(more) {
    var rows = $('manage-audit-rows');
    rows.textContent = '';
    entries.forEach(function (e) {
      var tr = el('tr');
      var th = el('th', 'manage-time', whenShort(e.time));
      th.scope = 'row';
      tr.appendChild(th);
      cell(tr, 'Who', e.actor || '-');
      cell(tr, 'What', OPS[e.op] || 'Other');
      cell(tr, 'Changes', changesText(e.changes));
      // The node's notes (what it checked, for a confirm or an automatic roll back) follow the result.
      var notes = Array.isArray(e.notes) && e.notes.length ? '. ' + e.notes.join(' ') : '';
      // A result that went wrong is bold as well as worded.
      cell(tr, 'Result', (RESULTS[e.result] || 'Other') + (e.error ? ': ' + e.error : '') + notes, e.result === 'ok' ? null : 'manage-bad');
      rows.appendChild(tr);
    });
    $('manage-audit-empty').hidden = entries.length > 0;
    $('manage-older').hidden = !more;
    $('manage-audit-card').hidden = false;
    paintLast();
    syncNav();
  }

  // The newest settings change that went through, which can be rolled back.
  function lastChange() {
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if ((e.op === 'settings' || e.op === 'rollback') && e.result === 'ok' && e.id) return e;
    }
    return null;
  }

  function paintLast() {
    var e = lastChange();
    var list = $('manage-last-list');
    list.textContent = '';
    $('manage-last-card').hidden = false;
    if (!e) {
      put($('manage-last'), 'Nothing to roll back: there is no settings change in the latest entries.' + (entriesMore ? ' Use Older entries below to look further back.' : ''));
      $('manage-rollback').hidden = true;
      $('manage-last-note').hidden = true;
      put($('manage-last-why'), '');
      $('manage-last-why').hidden = true;
      return;
    }
    put($('manage-last'), (e.op === 'rollback' ? 'A roll back' : 'A settings change') + ' by ' + (e.actor || 'someone') + ', ' + when(e.time) + ':');
    (e.changes || []).forEach(function (c) { list.appendChild(el('li', null, c.key + ': "' + c.from + '" to "' + c.to + '"')); });
    $('manage-rollback').hidden = false;
    $('manage-rollback').disabled = !canChange() || blocked('rollback');
    $('manage-last-note').hidden = false;
    var why = canChange() ? '' : VIEW_ONLY_WHY;
    put($('manage-last-why'), why);
    $('manage-last-why').hidden = !why;
    drawRetry();
  }

  function loadAudit(before) {
    var host = node.host;
    var q = '/api/manage/audit?host=' + encodeURIComponent(host) + (before !== undefined ? '&before=' + before : '');
    return getJson(q).then(function (r) {
      if (shown !== host) return;
      if (r.status !== 200) { fail('manage-error', errorOf(r)); return; }
      var got = Array.isArray(r.body.entries) ? r.body.entries : [];
      entries = before !== undefined ? entries.concat(got) : got;
      entriesMore = r.body.more === true;
      paintAudit(entriesMore);
    });
  }

  // ---- loading ----

  // keepEdits: the forms are built again with what the person typed (where the node's value is the same).
  function loadNode(message, keepEdits) {
    var host = node.host;
    return getJson('/api/manage/node?host=' + encodeURIComponent(host)).then(function (r) {
      if (shown !== host) return;
      if (r.status === 401 && r.body.signIn) return load();
      if (r.status !== 200) {
        state = null;
        put($('manage-node-h'), node.name);
        put($('manage-line'), '');
        $('manage-clock').hidden = true;
        $('manage-settings').hidden = true;
        $('manage-ret').hidden = true;
        $('manage-ret-edit').hidden = true;
        $('manage-restart-card').hidden = true;
        syncNav();
        say('');
        fail('manage-error', errorOf(r));
        return;
      }
      var edits = keepEdits ? takeEdits() : null;
      state = r.body;
      fail('manage-error', '');
      say(message || '');
      paintState(edits);
      // A confirm job that still runs (the page was loaded meanwhile): followed until it is over.
      if (jobRunning(state.confirm) && !retPoll) startRetPoll(host);
      return loadAudit();
    }).catch(function () { fail('manage-error', 'Could not reach the server. Try again later.'); });
  }

  function pick(host) {
    stopPoll();
    stopRetPoll();
    endRetry(false);
    var found = null;
    (data.nodes || []).forEach(function (n) { if (n.host === host) found = n; });
    if (!found) return;
    node = found;
    shown = host;
    state = null;
    entries = [];
    $('manage-ret-sections').textContent = '';
    $('manage-ret-shared').hidden = true;
    $('manage-ret-status').textContent = 'Loading the Reticulum configuration...';
    $('manage-ret').hidden = false;
    $('manage-ret-edit').hidden = true;
    $('manage-pending-line').hidden = true;
    syncNav();
    ['manage-form-error', 'manage-restart-error', 'manage-rollback-error', 'manage-ret-error', 'manage-error'].forEach(function (id) { fail(id, ''); });
    say('Loading ' + node.name + '...');
    return loadNode();
  }

  function load() {
    stopPoll();
    stopRetPoll();
    endRetry(false);
    return getJson('/api/manage').then(function (r) {
      if (r.status !== 200) {
        data = null;
        root.hidden = true;
        say(r.status === 401 ? 'Your session has ended. Sign in again to manage nodes.' : errorOf(r));
        return;
      }
      data = r.body;
      var nodes = Array.isArray(data.nodes) ? data.nodes : [];
      $('manage-view-only').hidden = Boolean(data.secondFactor);
      $('manage-wait').hidden = !(data.secondFactor && waiting());
      if (waiting()) $('manage-wait-until').textContent = new Date(data.nodeChangesFrom).toLocaleString();
      $('manage-none').hidden = nodes.length > 0;
      root.hidden = nodes.length === 0;
      if (nodes.length === 0) { say(''); return; }
      var select = $('manage-node');
      select.textContent = '';
      nodes.forEach(function (n) {
        var o = el('option', null, n.name === n.host ? n.host : n.name + ' (' + n.host + ')');
        o.value = n.host;
        select.appendChild(o);
      });
      var keep = node && nodes.some(function (n) { return n.host === node.host; }) ? node.host : nodes[0].host;
      select.value = keep;
      return pick(keep);
    }).catch(function () { say('Could not load the nodes. Try again later.'); });
  }

  $('manage-node').addEventListener('change', function () { pick($('manage-node').value); });

  // ---- changes ----

  // What the page does with the answer to a settings change or a roll back.
  // keepAfter: whether what the person typed stays in the form after the change went through (a Turn off
  // changes one thing and leaves the other edits alone; a Save or a roll back has used them).
  function afterChange(r, errorId, done, keepAfter) {
    if (!r) return;
    if (r.status === 200) return loadNode(done(r.body), keepAfter === true);
    fail(errorId, errorOf(r));
    // Changed elsewhere: the form is loaded again, and the words say so. Edits stay where they still fit.
    if (r.body && r.body.code === 'stale_revision') return loadNode('The settings were loaded again, because they changed elsewhere.', true);
  }

  function saveTarget() { return { button: $('manage-save'), note: $('manage-save-retry') }; }

  function savedText(b) {
    var n = Array.isArray(b.applied) ? b.applied.length : 0;
    var notes = Array.isArray(b.notes) && b.notes.length ? ' ' + b.notes.join(' ') : '';
    return 'Saved: ' + (n === 1 ? '1 setting' : n + ' settings') + ' changed.' + notes;
  }

  $('manage-form').addEventListener('submit', function (e) {
    e.preventDefault();
    if (!state || !canChange()) return;
    var c = changes();
    if (c.labels.length === 0) { fail('manage-form-error', 'Nothing to save: no setting was changed.'); return; }
    fail('manage-form-error', '');
    var host = node.host;
    var go = $('manage-save');
    go.disabled = true;
    confirmed('/api/manage/settings', { host: host, revision: $('manage-revision').value, changes: c.map }, {
      title: 'Save settings on ' + node.name,
      why: 'Changes ' + c.said.join(', ') + '.',
      action: 'Save'
    }).then(function (r) {
      if (shown !== host) return;
      if (r && r.status !== 200) startRetry(r, 'save', 'manage-form-error', saveTarget, function () { go.disabled = !canChange(); });
      return afterChange(r, 'manage-form-error', savedText);
    }).catch(function () { fail('manage-form-error', 'Could not reach the server. Try again.'); })
      .then(function () {
        go.disabled = !canChange() || blocked('save');
        // The dialog closed on a button that was off: the focus comes back to it.
        if (!go.disabled) focusOn(go);
      });
  });

  function turnOff(s) {
    if (!state || !canChange()) return;
    var host = node.host;
    var changesMap = {};
    changesMap[s.key] = 'false';
    confirmed('/api/manage/settings', { host: host, revision: $('manage-revision').value, changes: changesMap }, {
      title: 'Turn off ' + s.label + ' on ' + node.name,
      why: 'It can only be turned on again in the terminal on the node.',
      action: 'Turn off',
      danger: true
    }).then(function (r) {
      if (shown !== host) return;
      if (r && r.status !== 200) {
        startRetry(r, 'off:' + s.key, 'manage-form-error', function () { return offUi[s.key] || null; }, function () {
          var u = offUi[s.key];
          if (u) u.button.disabled = !isOn(s.value) || !canChange();
        });
      }
      var again = afterChange(r, 'manage-form-error', function () { return s.label + ' is turned off.'; }, true);
      // The button that was pressed is gone with the old form: the focus goes to the same row of the new one.
      return Promise.resolve(again).then(function () { if (r && r.status === 200) focusOn(offLabels[s.key]); });
    }).catch(function () { fail('manage-form-error', 'Could not reach the server. Try again.'); });
  }

  $('manage-rollback').addEventListener('click', function () {
    var last = lastChange();
    if (!last || !canChange()) return;
    var host = node.host;
    confirmed('/api/manage/rollback', { host: host, id: last.id }, {
      title: 'Roll back the last change on ' + node.name,
      why: 'Sets back ' + (last.changes || []).map(function (c) { return c.key + ' to "' + c.from + '"'; }).join(', ') + '.',
      action: 'Roll back'
    }).then(function (r) {
      if (shown !== host || !r) return;
      if (r.status === 200) {
        fail('manage-rollback-error', '');
        return loadNode('The change is rolled back.').then(function () { focusOn($('manage-last-h')); });
      }
      fail('manage-rollback-error', errorOf(r));
      startRetry(r, 'rollback', 'manage-rollback-error', function () { return { button: $('manage-rollback'), note: $('manage-rollback-retry') }; }, function () { $('manage-rollback').disabled = !canChange(); });
    }).catch(function () { fail('manage-rollback-error', 'Could not reach the server. Try again.'); });
  });

  // ---- restart, then asking every 3 seconds until the node says how it went ----

  function stopPoll() {
    if (poll) window.clearTimeout(poll.timer);
    poll = null;
  }

  function startPoll(host, id) {
    stopPoll();
    var started = Date.now();
    poll = { timer: null };
    var me = poll;
    function next() {
      me.timer = window.setTimeout(function () {
        if (poll !== me || shown !== host) return;
        getJson('/api/manage/node?host=' + encodeURIComponent(host)).then(function (r) {
          if (poll !== me || shown !== host) return;
          var rs = r.status === 200 && r.body.restart && r.body.restart.id === id ? r.body.restart : null;
          if (rs && rs.state !== 'restarting') {
            poll = null;
            var edits = takeEdits();
            state = r.body;
            paintState(edits);
            say(rs.state === 'up' ? 'Reticulum is back: every interface that was online is online again.' : 'Reticulum restarted, but not everything came back. See the node.');
            return loadAudit();
          }
          if (r.status === 429) { poll = null; say('The page stopped asking the node, as it asked too often. Reload the page in a while.'); return; }
          if (Date.now() - started >= POLL_LIMIT_MS) { poll = null; say('The node has not said after 2 minutes that Reticulum is back. Reload the page to check.'); if (state) paintState(takeEdits()); return; }
          next();
        }, function () {
          if (poll !== me) return;
          if (Date.now() - started >= POLL_LIMIT_MS) { poll = null; say('Could not reach the server. Reload the page to check the node.'); return; }
          next();
        });
      }, POLL_MS);
    }
    next();
  }

  $('manage-restart').addEventListener('click', function () {
    if (!state || !canChange()) return;
    var host = node.host;
    confirmed('/api/manage/restart', { host: host }, {
      title: 'Restart Reticulum on ' + node.name,
      why: 'Connections through this node drop for a moment.',
      action: 'Restart',
      danger: true
    }).then(function (r) {
      if (shown !== host || !r) return;
      if (r.status !== 202) {
        fail('manage-restart-error', errorOf(r));
        startRetry(r, 'restart', 'manage-restart-error', function () { return { button: $('manage-restart'), note: $('manage-restart-retry') }; }, paintRestart);
        return;
      }
      fail('manage-restart-error', '');
      say('Reticulum is restarting. This page checks every few seconds until it is back.');
      startPoll(host, r.body.id);
      paintRestart();
      focusOn($('manage-restart-h'));
    }).catch(function () { fail('manage-restart-error', 'Could not reach the server. Try again.'); });
  });

  $('manage-older').addEventListener('click', function () {
    var oldest = entries.length ? entries[entries.length - 1].seq : undefined;
    if (oldest === undefined) return;
    var b = $('manage-older');
    b.disabled = true;
    loadAudit(oldest).catch(function () { fail('manage-error', 'Could not reach the server. Try again.'); }).then(function () { b.disabled = false; });
  });

  load();
})();
