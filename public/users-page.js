// The users page (/users), for admins: every user from GET /api/users in a table (cards on a phone),
// a form to add a user, and a dialog for the choices of a change (role, new password). Every change
// is confirmed in the step-up dialog (step-up.js): the admin's password, and with their two-step
// sign-in on, a code from their app as well. It is a POST of JSON with the X-Rettui-Request header. The
// server decides everything; this page only shows what it says. Everything is set as text: nothing
// from the server becomes markup. A one-time password is shown once, with a copy button, and is
// cleared from the page when the admin is done with it.
(function () {
  'use strict';
  var root = document.getElementById('users');
  if (!root) return;
  var statusEl = document.getElementById('users-status');
  var data = null;
  // The change the dialog is for: {path, user, kind}.
  var pending = null;
  var opener = null;

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function when(iso) {
    if (!iso) return 'never';
    var d = new Date(iso);
    return isNaN(d.getTime()) ? 'unknown' : d.toLocaleString();
  }

  function say(text) { statusEl.textContent = text; }

  function api(path, body) {
    return fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-Rettui-Request': '1' },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) { return { status: r.status, body: b }; });
    });
  }

  function errorOf(r) {
    return r && r.body && r.body.error ? r.body.error : 'Something went wrong. Try again.';
  }

  // A change confirmed in the step-up dialog, which collects the password (and the code) and stays
  // open on a wrong one. When the sign in is older than 15 minutes, the password just given makes it
  // recent again (the server has not looked at the code yet) and the change is sent again. Gives the
  // answer, or null when the admin gave up or must sign in again.
  function confirmed(path, body, opts) {
    if (!window.rettuiStepUp) return Promise.resolve({ status: 0, body: { error: 'The page did not load completely. Reload it.' } });
    return window.rettuiStepUp.ask({
      title: opts.title,
      why: opts.why,
      action: opts.action,
      danger: opts.danger,
      secondFactor: Boolean(data && data.secondFactor),
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

  function cell(row, label, text, cls) {
    var td = el('td', cls, text);
    td.setAttribute('data-label', label);
    row.appendChild(td);
    return td;
  }

  function button(text, label, onClick, cls) {
    var b = el('button', cls, text);
    b.type = 'button';
    b.setAttribute('aria-label', label);
    b.addEventListener('click', function () { onClick(b); });
    return b;
  }

  function paint() {
    var rows = $('users-rows');
    rows.textContent = '';
    data.users.forEach(function (u) {
      var tr = el('tr');
      var th = el('th', 'users-name', u.name);
      th.scope = 'row';
      if (u.name === data.me) th.appendChild(el('span', 'acct-current', ' (you)'));
      tr.appendChild(th);
      cell(tr, 'Role', u.role);
      cell(tr, 'Source', u.source === 'config' ? 'Managed by config' : 'Website' + (u.mustChangePassword ? ' (must change password)' : ''));
      cell(tr, 'Two-step sign-in', u.secondFactor ? 'On' : 'Off');
      cell(tr, 'Devices', String(u.devices), 'num');
      cell(tr, 'Last sign in', when(u.lastLogin));
      cell(tr, 'Created', u.created ? when(u.created) : '-');
      var actions = cell(tr, 'Actions', undefined, 'users-actions');
      var self = u.name === data.me;
      if (u.source === 'store') {
        actions.appendChild(button('Role', 'Change the role of ' + u.name, function (b) { open(b, 'role', u); }));
        if (!self) actions.appendChild(button('Reset password', 'Reset the password of ' + u.name, function (b) { open(b, 'password', u); }));
      }
      if (!self && (u.secondFactor || u.devices > 0)) {
        actions.appendChild(button('Reset two-step', 'Reset the two-step sign-in of ' + u.name, function (b) { open(b, 'factor', u); }));
      }
      if (u.source === 'store') actions.appendChild(button('Delete', 'Delete ' + u.name, function (b) { open(b, 'delete', u); }, 'danger'));
      if (!actions.firstChild) actions.textContent = u.source === 'config' ? 'Change in the config file' : '-';
      rows.appendChild(tr);
    });
  }

  // Loads the list again; message, when given, is said once it is there (a success message said
  // before would be cleared).
  function load(message) {
    return fetch('/api/users', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (b) { return { status: r.status, body: b }; }); })
      .then(function (r) {
        if (r.status === 200) {
          data = r.body;
          root.hidden = false;
          say(message || '');
          paint();
          return;
        }
        data = null;
        root.hidden = true;
        say(r.status === 401 ? 'Your session has ended. Sign in again to manage users.' : errorOf(r));
      })
      .catch(function () { say('Could not load the users. Try again later.'); });
  }

  // ---- one-time passwords ----
  function showOtp(name, value) {
    $('users-otp-for').textContent = 'The one-time password for ' + name + ':';
    $('users-otp-value').textContent = value;
    $('users-otp').hidden = false;
    $('users-otp').focus();
  }

  $('users-otp-copy').addEventListener('click', function () {
    if (!navigator.clipboard) { say('Copying is not available here. Select the text instead.'); return; }
    navigator.clipboard.writeText($('users-otp-value').textContent).then(function () { say('The one-time password is copied.'); }, function () { say('Could not copy. Select the text instead.'); });
  });

  $('users-otp-done').addEventListener('click', function () {
    $('users-otp-value').textContent = '';
    $('users-otp-for').textContent = '';
    $('users-otp').hidden = true;
    say('');
    $('users-list-h').focus();
  });

  // ---- the password choice (one-time or typed) ----
  function wireChoice(generateId, typeId, inputId, labelId) {
    function sync() {
      var typed = $(typeId).checked;
      $(inputId).hidden = !typed;
      $(labelId).hidden = !typed;
      if (!typed) $(inputId).value = '';
    }
    $(generateId).addEventListener('change', sync);
    $(typeId).addEventListener('change', sync);
    return sync;
  }
  var syncNew = wireChoice('new-pw-generate', 'new-pw-type', 'new-password', 'new-password-label');
  var syncAct = wireChoice('act-pw-generate', 'act-pw-type', 'act-password', 'act-password-label');

  function setError(id, text, inputs) {
    $(id).textContent = text;
    (inputs || []).forEach(function (i) { $(i).setAttribute('aria-invalid', text ? 'true' : 'false'); });
  }

  // ---- add a user ----
  $('new-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var fields = ['new-name', 'new-password'];
    var name = $('new-name').value.trim();
    var typed = $('new-pw-type').checked;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(name)) { setError('new-error', 'Enter a name: 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit.', fields); $('new-name').focus(); return; }
    if (typed && Array.from($('new-password').value).length < 12) { setError('new-error', 'The password must be at least 12 characters.', fields); $('new-password').focus(); return; }
    setError('new-error', '', fields);
    var role = $('new-role').value;
    var body = { name: name, role: role };
    if (typed) body.newPassword = $('new-password').value;
    else body.generate = true;
    var go = $('new-submit');
    go.disabled = true;
    confirmed('/api/users/create', body, { title: 'Add ' + name + ' as ' + role, why: 'They must choose their own password when they first sign in.', action: 'Add user' }).then(function (r) {
      if (!r) return;
      if (r.status !== 200) { setError('new-error', errorOf(r), r.body && r.body.field === 'newPassword' ? ['new-password'] : ['new-name']); $(r.body && r.body.field === 'newPassword' ? 'new-password' : 'new-name').focus(); return; }
      $('new-name').value = '';
      $('new-password').value = '';
      return load(name + ' is added. They must choose their own password when they first sign in.').then(function () {
        if (r.body.oneTimePassword) showOtp(r.body.name, r.body.oneTimePassword);
      });
    }).catch(function () { setError('new-error', 'Could not reach the server. Try again.', fields); })
      .then(function () { go.disabled = false; });
  });

  // ---- the dialog for a change to one user ----
  var KINDS = {
    role: { path: '/api/users/role', title: 'Change the role', go: 'Change role', why: function (u) { return u.name + ' is signed out everywhere, and signs in again with the new role.'; } },
    password: { path: '/api/users/reset-password', title: 'Reset the password', go: 'Reset password', danger: true, why: function (u) { return 'The password of ' + u.name + ' stops working now, and they are signed out everywhere. They must choose a new one when they sign in with the one you set.'; } },
    factor: { path: '/api/users/reset-second-factor', title: 'Reset two-step sign-in', go: 'Reset two-step sign-in', danger: true, why: function (u) { return 'This turns off two-step sign-in for ' + u.name + ', removes their recovery codes and known devices, and signs them out everywhere. Their password alone then signs them in, until they set it up again.'; } },
    delete: { path: '/api/users/delete', title: 'Delete user', go: 'Delete', danger: true, why: function (u) { return 'This deletes ' + u.name + ' and signs them out everywhere. It cannot be undone.'; } }
  };

  // Role and password changes have choices, made in the first dialog; every change is then
  // confirmed in the step-up dialog, whose title and words say what will happen.
  function open(from, kind, user) {
    var k = KINDS[kind];
    if (kind === 'factor' || kind === 'delete') {
      run(kind, user, { name: user.name });
      return;
    }
    pending = { kind: kind, user: user };
    opener = from;
    $('act-title').textContent = k.title + ': ' + user.name;
    $('act-why').textContent = k.why(user);
    $('act-role').hidden = kind !== 'role';
    $('act-role-label').hidden = kind !== 'role';
    if (kind === 'role') $('act-role').value = user.role;
    $('act-pw').hidden = kind !== 'password';
    $('act-pw-generate').checked = true;
    // The server refuses a typed password for an admin.
    var adminTarget = kind === 'password' && user.role === 'admin';
    $('act-pw-type-row').hidden = adminTarget;
    $('act-pw-admin').hidden = !adminTarget;
    syncAct();
    setError('act-error', '', ['act-password']);
    $('act').showModal();
    (kind === 'role' ? $('act-role') : $('act-pw-generate')).focus();
  }

  $('act-cancel').addEventListener('click', function () { $('act').close(); });
  $('act').addEventListener('close', function () {
    $('act-password').value = '';
    if (pending === null) return;
    pending = null;
    if (opener && opener.isConnected) opener.focus();
    opener = null;
  });

  $('act-form').addEventListener('submit', function (e) {
    e.preventDefault();
    if (!pending) return;
    var p = pending;
    var body = { name: p.user.name };
    if (p.kind === 'role') {
      body.role = $('act-role').value;
      if (body.role === p.user.role) { setError('act-error', p.user.name + ' is ' + body.role + ' already.', []); $('act-role').focus(); return; }
    }
    if (p.kind === 'password') {
      if ($('act-pw-type').checked) {
        if (Array.from($('act-password').value).length < 12) { setError('act-error', 'The password must be at least 12 characters.', ['act-password']); $('act-password').focus(); return; }
        body.newPassword = $('act-password').value;
      } else body.generate = true;
    }
    // The choices are made: this dialog closes (the focus goes back to the row's button), and the
    // step-up dialog opens from there.
    $('act').close();
    run(p.kind, p.user, body);
  });

  function run(kind, user, body) {
    var k = KINDS[kind];
    var title = kind === 'role' ? 'Make ' + user.name + ' ' + body.role : k.title + ': ' + user.name;
    confirmed(k.path, body, { title: title, why: k.why(user), action: k.go, danger: k.danger }).then(function (r) {
      if (!r) return;
      if (r.status !== 200) { say(errorOf(r)); return; }
      if (r.body.signedOut) {
        say('Done. You are signed out, because you changed your own account.');
        location.assign('/');
        return;
      }
      var done = { role: user.name + ' now has the role ' + body.role + '.', password: 'The password of ' + user.name + ' is reset.', factor: 'Two-step sign-in of ' + user.name + ' is reset.', delete: user.name + ' is deleted.' };
      return load(done[kind]).then(function () {
        if (r.body.oneTimePassword) showOtp(user.name, r.body.oneTimePassword);
        else $('users-list-h').focus();
      });
    }).catch(function () { say('Could not reach the server. Try again.'); });
  }

  syncNew();
  load();
})();
