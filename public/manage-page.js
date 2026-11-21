// The manage page (/manage), for users with the manage or admin role: pick a node, see its version,
// network and clock, read its Reticulum config (read only), change the settings it allows, turn a service off, restart Reticulum, roll
// back the last settings change, and read the node's list of changes. Every change is confirmed
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
  var data = null;
  var node = null;
  var state = null;
  var entries = [];
  // Which node a request is for: an answer for a node no longer shown is dropped.
  var shown = null;
  var poll = null;
  // The inputs of the settings form, by key.
  var inputs = {};

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function say(text) { $('manage-status').textContent = text; }
  function fail(id, text) { $(id).textContent = text || ''; }

  function when(seconds) {
    if (typeof seconds !== 'number') return 'unknown';
    var d = new Date(seconds * 1000);
    return isNaN(d.getTime()) ? 'unknown' : d.toLocaleString();
  }

  function read(r) {
    return r.json().catch(function () { return {}; }).then(function (b) { return { status: r.status, body: b || {} }; });
  }

  function getJson(path) {
    return fetch(path, { credentials: 'same-origin', cache: 'no-store' }).then(read);
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

  function paintState() {
    $('manage-node-h').textContent = node.name === node.host ? node.host : node.name + ' (' + node.host + ')';
    $('manage-line').textContent = statusLine(state);
    var warn = state.clock && state.clock.warning;
    $('manage-clock').hidden = !warn;
    $('manage-clock').textContent = warn || '';
    var rt = restartText(state.restart);
    $('manage-restart-state').hidden = !rt;
    $('manage-restart-state').textContent = rt;
    $('manage-revision').value = state.settings_revision || '';
    paintFields();
    paintReticulum();
    var later = typeof state.restart_allowed_at === 'number' && state.restart_allowed_at * 1000 > Date.now();
    var busy = Boolean(state.restart && state.restart.state === 'restarting') || poll !== null;
    $('manage-restart').disabled = !canChange() || later || busy;
    fail('manage-restart-error', later ? 'The node allows the next restart at ' + when(state.restart_allowed_at) + '.' : '');
    $('manage-settings').hidden = false;
    $('manage-restart-card').hidden = false;
  }

  // One input per setting the node may change, grouped in fieldsets; a service that can only be
  // turned off is a button instead.
  function paintFields() {
    var box = $('manage-fields');
    box.textContent = '';
    inputs = {};
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
    $('manage-save').disabled = !canChange() || !(state.settings || []).some(function (s) { return s.access === 'change'; });
  }

  function field(s, id) {
    var row = el('div', 'manage-field');
    var helpId = id + '-help';
    var help = s.help ? el('p', 'note', s.help) : null;
    if (help) help.id = helpId;
    if (s.access === 'turn_off_only') {
      var on = isOn(s.value);
      row.appendChild(el('p', 'manage-label', s.label + ': ' + (on ? 'on' : 'off')));
      if (help) row.appendChild(help);
      var b = el('button', 'danger', 'Turn off');
      b.type = 'button';
      b.setAttribute('aria-label', 'Turn off ' + s.label);
      if (help) b.setAttribute('aria-describedby', helpId);
      b.disabled = !on || !canChange();
      b.addEventListener('click', function () { turnOff(s); });
      var actions = el('div', 'login-actions');
      actions.appendChild(b);
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
    input.setAttribute('aria-describedby', (help ? helpId + ' ' : '') + 'manage-form-error');
    var label = el('label', null, s.label + (s.kind === 'optional' ? ' (may be empty)' : ''));
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
    (state.settings || []).forEach(function (s) {
      if (s.access !== 'change' || !Object.prototype.hasOwnProperty.call(inputs, s.key)) return;
      var input = inputs[s.key];
      var now = s.kind === 'toggle' ? (input.checked ? 'true' : 'false') : input.value;
      var was = s.kind === 'toggle' ? (isOn(s.value) ? 'true' : 'false') : s.value;
      if (now !== was) { out[s.key] = now; list.push(s.label); }
    });
    return { map: out, labels: list };
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
      $('manage-ret-status').textContent = 'This node does not say what its Reticulum config holds.';
      return;
    }
    var said = [];
    if (r.sections.length === 0) said.push('The node lists no Reticulum configuration.');
    if (r.truncated === true) said.push('Part of the config is not shown.');
    $('manage-ret-status').textContent = said.join(' ');
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

  // ---- the node's list of changes ----

  var OPS = { settings: 'Settings', restart: 'Restart', rollback: 'Roll back', reticulum: 'Reticulum config', confirm: 'Confirm', auto_rollback: 'Rolled back by itself', auth_failures: 'Refused requests' };
  var RESULTS = { ok: 'Done', refused: 'Refused', failed: 'Failed', rolled_back: 'Rolled back' };

  function changesText(list) {
    if (!list || list.length === 0) return '-';
    return list.map(function (c) { return c.key + ': "' + c.from + '" to "' + c.to + '"'; }).join('; ');
  }

  function cell(row, label, text) {
    var td = el('td', null, text);
    td.setAttribute('data-label', label);
    row.appendChild(td);
  }

  function paintAudit(more) {
    var rows = $('manage-audit-rows');
    rows.textContent = '';
    entries.forEach(function (e) {
      var tr = el('tr');
      var th = el('th', null, when(e.time));
      th.scope = 'row';
      tr.appendChild(th);
      cell(tr, 'Who', e.actor || '-');
      cell(tr, 'What', OPS[e.op] || 'Other');
      cell(tr, 'Changes', changesText(e.changes));
      cell(tr, 'Result', (RESULTS[e.result] || 'Other') + (e.error ? ': ' + e.error : ''));
      rows.appendChild(tr);
    });
    $('manage-audit-empty').hidden = entries.length > 0;
    $('manage-older').hidden = !more;
    $('manage-audit-card').hidden = false;
    paintLast();
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
      $('manage-last').textContent = 'No settings change to roll back in the latest entries.';
      $('manage-rollback').hidden = true;
      return;
    }
    $('manage-last').textContent = (e.op === 'rollback' ? 'A roll back' : 'A settings change') + ' by ' + (e.actor || 'someone') + ', ' + when(e.time) + ':';
    (e.changes || []).forEach(function (c) { list.appendChild(el('li', null, c.key + ': "' + c.from + '" to "' + c.to + '"')); });
    $('manage-rollback').hidden = false;
    $('manage-rollback').disabled = !canChange();
  }

  function loadAudit(before) {
    var host = node.host;
    var q = '/api/manage/audit?host=' + encodeURIComponent(host) + (before !== undefined ? '&before=' + before : '');
    return getJson(q).then(function (r) {
      if (shown !== host) return;
      if (r.status !== 200) { fail('manage-error', errorOf(r)); return; }
      var got = Array.isArray(r.body.entries) ? r.body.entries : [];
      entries = before !== undefined ? entries.concat(got) : got;
      paintAudit(r.body.more === true);
    });
  }

  // ---- loading ----

  function loadNode(message) {
    var host = node.host;
    return getJson('/api/manage/node?host=' + encodeURIComponent(host)).then(function (r) {
      if (shown !== host) return;
      if (r.status === 401 && r.body.signIn) return load();
      if (r.status !== 200) {
        state = null;
        $('manage-node-h').textContent = node.name;
        $('manage-line').textContent = '';
        $('manage-clock').hidden = true;
        $('manage-settings').hidden = true;
        $('manage-ret').hidden = true;
        $('manage-restart-card').hidden = true;
        say('');
        fail('manage-error', errorOf(r));
        return;
      }
      state = r.body;
      fail('manage-error', '');
      say(message || '');
      paintState();
      return loadAudit();
    }).catch(function () { fail('manage-error', 'Could not reach the server. Try again later.'); });
  }

  function pick(host) {
    stopPoll();
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
    ['manage-form-error', 'manage-restart-error', 'manage-rollback-error', 'manage-error'].forEach(function (id) { fail(id, ''); });
    say('Loading ' + node.name + '...');
    return loadNode();
  }

  function load() {
    stopPoll();
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
  function afterChange(r, errorId, done) {
    if (!r) return;
    if (r.status === 200) return loadNode(done(r.body));
    fail(errorId, errorOf(r));
    // Changed elsewhere: the form is loaded again, and the words say so.
    if (r.body && r.body.code === 'stale_revision') return loadNode('The settings were loaded again, because they changed elsewhere.');
  }

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
      why: 'Changes ' + c.labels.join(', ') + '.',
      action: 'Save'
    }).then(function (r) {
      if (shown !== host) return;
      return afterChange(r, 'manage-form-error', savedText);
    }).catch(function () { fail('manage-form-error', 'Could not reach the server. Try again.'); })
      .then(function () { go.disabled = !canChange(); });
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
      return afterChange(r, 'manage-form-error', function () { return s.label + ' is turned off.'; });
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
      if (r.status === 200) { fail('manage-rollback-error', ''); return loadNode('The change is rolled back.'); }
      fail('manage-rollback-error', errorOf(r));
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
            state = r.body;
            paintState();
            say(rs.state === 'up' ? 'Reticulum is back: every interface that was online is online again.' : 'Reticulum restarted, but not everything came back. See the node.');
            return loadAudit();
          }
          if (r.status === 429) { poll = null; say('The page stopped asking the node, as it asked too often. Reload the page in a while.'); return; }
          if (Date.now() - started >= POLL_LIMIT_MS) { poll = null; say('The node has not said after 2 minutes that Reticulum is back. Reload the page to check.'); if (state) paintState(); return; }
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
      if (r.status !== 202) { fail('manage-restart-error', errorOf(r)); return; }
      fail('manage-restart-error', '');
      say('Reticulum is restarting. This page checks every few seconds until it is back.');
      $('manage-restart').disabled = true;
      startPoll(host, r.body.id);
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
