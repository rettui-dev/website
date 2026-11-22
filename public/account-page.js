// The account page (/account): profile, password, two-step sign-in (an app code, passkeys and
// recovery codes), sessions and known devices of
// whoever is signed in, from GET /api/account. Every change is a POST of JSON with the X-Rettui-Request header. A
// change needs a sign in from the last 15 minutes; when the server says it is older, a dialog asks
// for the password and the change is sent again. Changing the password, new recovery codes and
// turning two-step sign-in off ask in the step-up dialog (step-up.js) for the password and, with
// a second step on, a passkey, a code from the app or a recovery code as well; setting up the app code
// with nothing else on asks there for the password only. A passkey is made in two steps: the server
// gives options (after the step-up), the browser makes the passkey (passkey.js), and the answer goes
// back to the server.
// The LXMF alert addresses (shown only when the site has a bridge that takes users' own addresses; up to 3) are
// added, confirmed one by one with the 6-digit code the site sends to each, and removed in the step-up dialog
// (confirmed(), as for a passkey: the password, and the second step when one is on); a new code is sent with
// send(): the recent password, nothing more.
// A page refresh (load) paints only what changed: a node whose text, state or list is the same is not written
// again, and the lists are not rebuilt, so a field the visitor is typing in (the rename of a passkey, the code)
// is never replaced or hidden by a refresh, and password managers see a page that holds still.
// Everything is set as text: nothing from the server becomes markup. The QR code is drawn from its
// rows of modules as SVG elements.
(function () {
  'use strict';
  var root = document.getElementById('acct');
  if (!root) return;
  var statusEl = document.getElementById('acct-status');
  var signinBox = document.getElementById('acct-signin');
  var data = null;
  var reauth = null;
  var SVG = 'http://www.w3.org/2000/svg';

  var CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
  // The buttons of each passkey in the list, by passkey id, so the focus can go back to one.
  var passkeyButtons = {};
  // The note above the passkeys, as account.html words it (kept to put back).
  var DEFAULT_PASSKEYS_NOTE = document.getElementById('passkeys-note') ? document.getElementById('passkeys-note').textContent : '';

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

  // Writes only when the value differs, so a refresh with the same data changes nothing in the page.
  function setText(e, text) { if (e.textContent !== text) e.textContent = text; }
  function setHidden(e, hidden) { if (e.hidden !== hidden) e.hidden = hidden; }
  function setValue(e, value) { if (e.value !== value) e.value = value; }
  function setChecked(e, checked) { if (e.checked !== checked) e.checked = checked; }
  // What a list was last built from: a list is built again only when this changes.
  var shown = {};
  function changed(key, value) {
    var sig = JSON.stringify(value);
    if (shown[key] === sig) return false;
    shown[key] = sig;
    return true;
  }
  // The cards that paintPasskeys, the recovery codes and paintLxmf show or hide themselves.
  var OWN_VISIBILITY = { 'acct-passkeys': true, 'acct-recovery': true, 'acct-lxmf': true };

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

  // Sends a change. When the sign in is too old, asks for the password and sends it again. Gives the
  // answer, or null when the visitor gave up.
  function send(path, body) {
    return api(path, body).then(function (r) {
      if (r.status === 403 && r.body.reauth) {
        return askPassword().then(function (ok) { return ok ? api(path, body) : null; });
      }
      if (r.status === 401 && r.body.signIn) {
        load();
        return null;
      }
      return r;
    });
  }

  // A change confirmed in the step-up dialog: the dialog collects the password (and the code), and
  // stays open on a wrong one. When the sign in is older than 15 minutes, the password just given
  // makes it recent again (the server has not looked at the code yet), and the change is sent again.
  // Gives the answer, or null when the visitor gave up or must sign in again.
  // The ways this account can confirm a change besides the password: the server lists them.
  function stepUpMethods() {
    if (data && Array.isArray(data.stepUpMethods)) return data.stepUpMethods;
    return data && data.totp && data.totp.enabled ? ['totp', 'recovery'] : [];
  }

  function secondFactorOn() {
    if (!data) return false;
    return typeof data.secondFactor === 'boolean' ? data.secondFactor : Boolean(data.totp && data.totp.enabled);
  }

  function passkeyList() {
    return data && data.passkeys && Array.isArray(data.passkeys.list) ? data.passkeys.list : [];
  }

  function canPasskey() {
    return Boolean(window.rettuiPasskey) && window.rettuiPasskey.supported();
  }

  function confirmed(path, body, opts) {
    if (!window.rettuiStepUp) return Promise.resolve({ status: 0, body: { error: 'The page did not load completely. Reload it.' } });
    return window.rettuiStepUp.ask({
      title: opts.title,
      why: opts.why,
      action: opts.action,
      danger: opts.danger,
      secondFactor: !opts.passwordOnly && secondFactorOn(),
      methods: opts.passwordOnly ? [] : stepUpMethods(),
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

  function errorOf(r) {
    return r && r.body && r.body.error ? r.body.error : 'Something went wrong. Try again.';
  }

  // The dialog that asks for the password again. Resolves true once the server took it.
  function askPassword() {
    return new Promise(function (resolve) {
      if (!reauth) buildReauth();
      reauth.resolve = resolve;
      reauth.done = false;
      reauth.back = document.activeElement;
      $('reauth-password').value = '';
      $('reauth-error').textContent = '';
      reauth.dlg.showModal();
      $('reauth-password').focus();
    });
  }

  function buildReauth() {
    var dlg = el('dialog', 'login');
    dlg.id = 'reauth';
    dlg.setAttribute('aria-labelledby', 'reauth-title');
    var form = el('form', 'login-form');
    form.noValidate = true;
    var title = el('h2', null, 'Confirm it is you');
    title.id = 'reauth-title';
    var why = el('p', 'note login-why', 'You have not given your password in the last 15 minutes (signing in with a passkey does not count). Enter it to go on.');
    why.id = 'reauth-why';
    var err = el('p', 'login-error');
    err.id = 'reauth-error';
    err.setAttribute('role', 'alert');
    var label = el('label', null, 'Password');
    label.htmlFor = 'reauth-password';
    var input = el('input');
    input.id = 'reauth-password';
    input.type = 'password';
    input.autocomplete = 'current-password';
    input.maxLength = 1024;
    input.required = true;
    input.setAttribute('aria-describedby', 'reauth-why reauth-error');
    var actions = el('div', 'login-actions');
    var go = el('button', 'primary', 'Continue');
    go.type = 'submit';
    var cancel = el('button', null, 'Cancel');
    cancel.type = 'button';
    actions.appendChild(go);
    actions.appendChild(cancel);
    [title, why, err, label, input, actions].forEach(function (x) { form.appendChild(x); });
    dlg.appendChild(form);
    document.body.appendChild(dlg);
    reauth = { dlg: dlg, resolve: null, done: false, back: null };
    cancel.addEventListener('click', function () { dlg.close(); });
    dlg.addEventListener('close', function () {
      var r = reauth.resolve;
      reauth.resolve = null;
      if (reauth.back && reauth.back.isConnected) reauth.back.focus();
      if (r) r(reauth.done);
    });
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (!input.value) {
        err.textContent = 'Enter your password.';
        input.focus();
        return;
      }
      go.disabled = true;
      api('/api/account/reauth', { password: input.value })
        .then(function (r) {
          if (r.status === 200 && r.body.ok) {
            reauth.done = true;
            input.value = '';
            dlg.close();
            return;
          }
          err.textContent = errorOf(r);
          input.value = '';
          input.focus();
        })
        .catch(function () { err.textContent = 'Could not reach the server. Try again.'; })
        .then(function () { go.disabled = false; });
    });
  }

  function setFormError(id, text, inputs) {
    $(id).textContent = text;
    (inputs || []).forEach(function (i) { $(i).setAttribute('aria-invalid', text ? 'true' : 'false'); });
  }

  // Runs a change from a button or form: the button is off while it runs.
  function busy(button, label, job) {
    if (button.disabled) return;
    var text = button.textContent;
    button.disabled = true;
    button.textContent = label;
    job().catch(function () { say('Could not reach the server. Try again.'); }).then(function () {
      button.disabled = false;
      button.textContent = text;
    });
  }

  function paint() {
    var must = data.mustChangePassword === true;
    setText($('acct-name'), data.name);
    setText($('acct-role'), data.role);
    setText($('acct-last'), when(data.lastLogin));
    setHidden($('acct-config-note'), !data.managedByConfig);
    setHidden($('acct-users'), data.canManageUsers !== true);
    // The manage page checks the role again; this only shows the way there.
    setHidden($('acct-manage'), !((data.role === 'manage' || data.role === 'admin') && !must));
    // A password an admin set: the password change is all there is until a new one is chosen.
    setHidden($('acct-must-change'), !must);
    // The cards that decide for themselves below are left out here: setting them twice would show and hide a
    // card with fields in it on every refresh.
    Array.prototype.forEach.call(document.querySelectorAll('[data-after-password]'), function (x) { if (!OWN_VISIBILITY[x.id]) setHidden(x, must); });
    setHidden($('pw-config'), data.canChangePassword);
    setHidden($('pw-form'), !data.canChangePassword);
    // Only offered while there are passkeys to remove.
    setHidden($('pw-remove-box'), passkeyList().length === 0);
    // Ticked by default: a passkey someone planted keeps signing in after the password changes. With none
    // listed the box is hidden but still ticked, and sent: a passkey added since the list was loaded goes too.
    if (passkeyList().length === 0) setChecked($('pw-remove'), true);
    // For password managers: the name the new password belongs to.
    setValue($('pw-user'), data.name);
    var on = Boolean(data.totp && data.totp.enabled);
    var keys = passkeyList().length;
    setText($('totp-state'), on
      ? (keys > 0 ? 'On: after your password you can also use a code from your app.' : 'On: signing in needs your password and a code from your app.')
      : (keys > 0 ? 'Off: no app code is set up. Your passkeys are your second step.' : 'Off: your password alone signs you in.'));
    setHidden($('totp-off'), on || !$('totp-setup-box').hidden);
    setHidden($('sessions-end'), data.sessions.length < 2);
    setHidden($('totp-on'), !on);
    // Recovery codes belong to any second step, not just the app code.
    var left = typeof data.recoveryCodesLeft === 'number' ? data.recoveryCodesLeft : on && data.totp ? data.totp.recoveryCodesLeft : 0;
    setText($('codes-left'), left === 1 ? '1 recovery code left.' : left + ' recovery codes left.');
    setHidden($('codes-on'), !secondFactorOn() || !$('codes-box').hidden);
    if (changed('sessions', data.sessions)) {
      var list = $('sessions-list');
      list.textContent = '';
      data.sessions.forEach(function (s) {
        var li = el('li');
        li.appendChild(el('span', null, 'Signed in ' + when(s.created) + ', last used ' + when(s.lastSeen)));
        if (s.current) li.appendChild(el('strong', 'acct-current', ' (this browser)'));
        list.appendChild(li);
      });
    }
    setHidden($('acct-passkeys'), must || !data.passkeys);
    setHidden($('acct-recovery'), must || !(secondFactorOn() || !$('codes-box').hidden));
    paintPasskeys();
    paintLxmf();
    paintDevices();
  }

  // The LXMF alerts card: hidden unless the server says the site has a bridge for it. The card holds, top to
  // bottom, its state, the addresses (each with its Remove button), the form to add one, the form to confirm
  // one that waits for its code, and the node alerts choice.
  function paintLxmf() {
    var l = data.lxmf;
    var card = $('acct-lxmf');
    setHidden(card, data.mustChangePassword === true || !l || l.available !== true);
    if (card.hidden) return;
    var items = Array.isArray(l.addresses) ? l.addresses : [];
    var max = typeof l.max === 'number' ? l.max : 3;
    var count = typeof l.count === 'number' ? l.count : items.length;
    var waiting = items.filter(function (a) { return !a.confirmed; });
    var live = items.length - waiting.length;
    var state;
    if (count === 0) state = 'No address is set.';
    else if (l.hidden) state = (count === 1 ? 'An address is set. It is' : count + ' addresses are set. They are') + ' not shown until you give your password in this session.';
    else if (live === 0) state = 'No address is confirmed yet. Nothing is sent until you confirm one.';
    else state = 'Alerts go to ' + live + (live === 1 ? ' address' : ' addresses') + '. You have ' + count + ' of ' + max + '.';
    setText($('lxmf-state'), state);
    setHidden($('lxmf-hidden'), l.hidden !== true);
    // The addresses.
    setHidden($('lxmf-list-box'), items.length === 0);
    if (changed('lxmf-list', items.map(function (a) { return [a.address, a.confirmed === true]; }))) {
      var list = $('lxmf-list');
      list.textContent = '';
      items.forEach(function (a) {
        var li = el('li', 'acct-passkey');
        li.appendChild(el('code', 'acct-passkey-name', a.address));
        li.appendChild(el('span', 'acct-passkey-info', a.confirmed ? 'Confirmed: alerts about your account go here.' : 'Waiting for the code. Nothing is sent here until you confirm it.'));
        var actions = el('div', 'login-actions');
        var remove = el('button', null, 'Remove');
        remove.type = 'button';
        remove.setAttribute('aria-label', 'Remove the LXMF address ' + a.address);
        remove.addEventListener('click', function () { removeLxmf(remove, a.address); });
        actions.appendChild(remove);
        li.appendChild(actions);
        list.appendChild(li);
      });
    }
    // The test alert: offered once an address is confirmed (and shown, so, with the list).
    var canTest = l.confirmed === true && items.length > 0;
    setHidden($('lxmf-test-box'), !canTest);
    setHidden($('lxmf-test-help'), !canTest);
    if (!canTest) setText($('lxmf-test-result'), '');
    // Adding.
    var full = count >= max;
    setHidden($('lxmf-set-form'), full);
    setHidden($('lxmf-full'), !full);
    setText($('lxmf-full'), 'You have ' + max + ' LXMF addresses, the most allowed. Remove one to add another.');
    // Confirming: one form, for the address picked in the list of those that wait.
    setHidden($('lxmf-confirm-form'), waiting.length === 0);
    var pick = $('lxmf-code-for');
    if (changed('lxmf-waiting', waiting.map(function (a) { return a.address; }))) {
      var keep = wanted || pick.value;
      pick.textContent = '';
      waiting.forEach(function (a) {
        var o = el('option', null, a.address);
        o.value = a.address;
        pick.appendChild(o);
      });
      if (waiting.length > 0) pick.value = waiting.some(function (a) { return a.address === keep; }) ? keep : waiting[0].address;
    } else if (wanted && waiting.some(function (a) { return a.address === wanted; })) {
      setValue(pick, wanted);
    }
    wanted = null;
    paintCodeHelp();
    // Node alerts.
    setHidden($('lxmf-nodes-form'), !(l.confirmed === true && l.canNodeAlerts === true));
    setChecked($('lxmf-nodes'), l.nodeAlerts === true);
    if ($('lxmf-nodes-form').hidden) setText($('lxmf-nodes-status'), '');
  }

  // The words under the code field, for the address picked.
  function paintCodeHelp() {
    var items = data && data.lxmf && Array.isArray(data.lxmf.addresses) ? data.lxmf.addresses : [];
    var at = $('lxmf-code-for').value;
    var mine = items.filter(function (a) { return a.address === at; })[0];
    setText($('lxmf-code-help'), (mine && mine.codeExpiresAt ? 'The code works until ' + when(mine.codeExpiresAt) + '. You can try to confirm 5 times an hour from one session, and 10 times an hour in all. ' : 'No code is waiting: send a new one. ') + 'A message can take a while to arrive over LXMF. You can have up to 3 codes an hour.');
  }

  // The passkeys: what the server lists, and what can be done here. A passkey made for another address
  // is listed, so it can be removed, but it cannot be used here.
  function paintPasskeys() {
    var p = data.passkeys;
    var list = $('passkeys-list');
    if (!p) { list.textContent = ''; passkeyButtons = {}; shown.passkeys = null; return; }
    var items = passkeyList();
    var max = typeof p.max === 'number' ? p.max : 10;
    var here = p.available === true;
    var browser = canPasskey();
    // Where passkeys can also sign in on their own, the note says so (the file's words are true without that).
    setText($('passkeys-note'), p.signIn === true && here
      ? "A passkey can sign you in on its own: press 'Sign in with a passkey' and confirm on your device. It also works as the second step after your password. Passkeys made on phones, computers and password managers usually work on their own. Some security keys only work as the second step: if yours does not show up, add it again here."
      : DEFAULT_PASSKEYS_NOTE);
    setHidden($('passkeys-unavailable'), here);
    setText($('passkeys-unavailable'), p.reason === 'no-address'
      ? "Passkeys need this site's https address in the config file (site.url, or SITE_URL)."
      : 'Passkeys are not available on this site.');
    setHidden($('passkeys-none'), items.length > 0);
    setHidden($('passkeys-browser'), !here || browser);
    var full = here && items.length >= max;
    setHidden($('passkeys-full'), !full);
    setText($('passkeys-full'), 'You have ' + items.length + ' passkeys, the most allowed. Remove one first.');
    setHidden($('passkey-add-form'), !here || !browser || full);
    // The list is built again only when what it shows changed (or to leave a rename), so a rename in progress
    // is not replaced by a refresh that brings nothing new.
    if (!changed('passkeys', items)) return;
    list.textContent = '';
    passkeyButtons = {};
    items.forEach(function (pk) {
      var li = el('li', 'acct-passkey');
      li.appendChild(el('strong', 'acct-passkey-name', pk.name));
      li.appendChild(el('span', 'acct-passkey-info', 'Added ' + when(pk.created) + ', last used ' + when(pk.lastUsed) + '. ' + (pk.synced ? 'Synced: also on your other devices.' : 'Device-bound: stays on one device or key.')));
      if (!pk.here) li.appendChild(el('strong', 'users-warning', 'Not usable at this address.'));
      var actions = el('div', 'login-actions');
      var rename = el('button', null, 'Rename');
      rename.type = 'button';
      rename.setAttribute('aria-label', 'Rename the passkey ' + pk.name);
      rename.addEventListener('click', function () { startRename(li, pk); });
      var remove = el('button', null, 'Remove');
      remove.type = 'button';
      remove.setAttribute('aria-label', 'Remove the passkey ' + pk.name);
      remove.addEventListener('click', function () { removePasskey(remove, pk); });
      actions.appendChild(rename);
      actions.appendChild(remove);
      li.appendChild(actions);
      passkeyButtons[pk.id] = { rename: rename, remove: remove };
      list.appendChild(li);
    });
  }

  // Known devices: no name is known for one, so each is told apart by when it was first and last used.
  function paintDevices() {
    var devices = data.devices || [];
    var list = $('devices-list');
    setHidden($('devices-none'), devices.length > 0);
    var others = devices.filter(function (d) { return !d.current; }).length;
    setHidden($('devices-others'), others === 0);
    if (!changed('devices', devices)) return;
    list.textContent = '';
    devices.forEach(function (d) {
      var li = el('li');
      var label = 'First used ' + when(d.created) + ', last used ' + when(d.lastUsed);
      li.appendChild(el('span', null, label));
      if (d.current) li.appendChild(el('strong', 'acct-current', ' (this browser)'));
      var remove = el('button', null, 'Remove');
      remove.type = 'button';
      remove.setAttribute('aria-label', 'Remove the device ' + label.charAt(0).toLowerCase() + label.slice(1));
      remove.addEventListener('click', function () { removeDevice(remove, d.id); });
      li.appendChild(document.createTextNode(' '));
      li.appendChild(remove);
      list.appendChild(li);
    });
  }

  function removeDevice(button, id) {
    busy(button, 'Removing...', function () {
      return send('/api/account/devices/remove', { device: id }).then(function (r) {
        if (!r) return;
        if (r.status !== 200) { say(errorOf(r)); return; }
        say('The device is removed and signed out. It is held back like any other browser until you sign in there again.');
        return load().then(function () { $('acct-devices-h').focus(); });
      });
    });
  }

  function load() {
    return fetch('/api/account', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (b) { return { status: r.status, body: b }; }); })
      .then(function (r) {
        if (r.status === 200) {
          data = r.body;
          signinBox.hidden = true;
          root.hidden = false;
          say('');
          paint();
          return;
        }
        data = null;
        root.hidden = true;
        signinBox.hidden = r.status !== 401;
        say(r.status === 401 ? '' : 'There are no accounts on this site.');
      })
      .catch(function () { say('Could not load your account. Try again later.'); });
  }

  // The QR code: a white square with a quiet zone of four modules, dark modules as one path.
  function drawQr(qr) {
    var box = $('totp-qr');
    box.textContent = '';
    if (!qr || !qr.rows) return;
    var quiet = 4;
    var full = qr.size + 2 * quiet;
    var svg = document.createElementNS(SVG, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + full + ' ' + full);
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'QR code for your authenticator app');
    svg.setAttribute('shape-rendering', 'crispEdges');
    var bg = document.createElementNS(SVG, 'rect');
    bg.setAttribute('width', String(full));
    bg.setAttribute('height', String(full));
    bg.setAttribute('fill', '#fff');
    svg.appendChild(bg);
    var d = '';
    qr.rows.forEach(function (row, y) {
      for (var x = 0; x < row.length; x++) if (row.charAt(x) === '1') d += 'M' + (x + quiet) + ' ' + (y + quiet) + 'h1v1h-1z';
    });
    var path = document.createElementNS(SVG, 'path');
    path.setAttribute('d', d);
    path.setAttribute('fill', '#000');
    svg.appendChild(path);
    box.appendChild(svg);
  }

  function showCodes(codes) {
    var list = $('codes-list');
    list.textContent = '';
    codes.forEach(function (c) { list.appendChild(el('li', null, c)); });
    $('acct-recovery').hidden = false;
    $('codes-box').hidden = false;
    $('codes-on').hidden = true;
    $('codes-done').focus();
  }

  function codesText() {
    var out = [];
    var items = $('codes-list').children;
    for (var i = 0; i < items.length; i++) out.push(items[i].textContent);
    return 'Recovery codes for ' + (data ? data.name : '') + ' on ' + location.host + '\n' + out.join('\n') + '\n';
  }

  function copyText(text, done) {
    if (!navigator.clipboard) { say('Copying is not available here. Select the text instead.'); return; }
    navigator.clipboard.writeText(text).then(function () { say(done); }, function () { say('Could not copy. Select the text instead.'); });
  }

  // ---- password ----
  $('pw-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var next = $('pw-next');
    var again = $('pw-again');
    var fields = ['pw-next', 'pw-again'];
    if (Array.from(next.value).length < 12) { setFormError('pw-error', 'The new password must be at least 12 characters.', fields); next.focus(); return; }
    if (next.value !== again.value) { setFormError('pw-error', 'The two new passwords are not the same.', fields); again.focus(); return; }
    setFormError('pw-error', '', fields);
    busy($('pw-submit'), 'Changing...', function () {
      // Whenever the box is ticked, seen or not: a passkey planted after the list was loaded goes too.
      var remove = $('pw-remove').checked === true;
      var sent = { next: next.value };
      if (remove) sent.removeOtherPasskeys = true;
      return confirmed('/api/account/password', sent, { title: 'Change your password', why: 'Your new password takes the place of the current one, and you are signed out everywhere else.', action: 'Change password' }).then(function (r) {
        if (!r) return;
        if (r.status === 200) {
          next.value = again.value = '';
          // A passkey keeps signing in without the password: the visitor is told to look at the list.
          // Said after the account is loaded again, which clears the line.
          var keeps = data && data.passkeys && data.passkeys.signIn === true && passkeyList().length > 0 && !remove;
          var count = r.body && typeof r.body.removedPasskeys === 'number' ? r.body.removedPasskeys : null;
          return load().then(function () {
            $('pw-remove').checked = true;
            if (count !== null) say('Your password is changed. You are signed out everywhere else. ' + (count === 0 ? 'You had no other passkeys to remove.' : count === 1 ? '1 passkey was removed.' : count + ' passkeys were removed.') + (passkeyList().length === 0 ? ' You can add a passkey again below.' : ''));
            else say('Your password is changed. You are signed out everywhere else.' + (keeps ? ' Your passkeys can still sign you in without the password. Check the list below and remove any you do not know.' : ''));
          });
        }
        setFormError('pw-error', errorOf(r), r.body && r.body.field === 'next' ? fields : []);
        next.focus();
      });
    });
  });

  // ---- two-step sign-in ----
  $('totp-setup-form').addEventListener('submit', function (e) {
    e.preventDefault();
    busy($('totp-setup'), 'Starting...', function () {
      // Only the password: two-step sign-in is not on yet. The first code from the app turns it on.
      return confirmed('/api/account/totp/setup', {}, { title: 'Set up an app code', why: 'Next you add this site to your authenticator app.', action: 'Continue', passwordOnly: !secondFactorOn() }).then(function (r) {
        if (!r) return;
        if (r.status !== 200) { setFormError('totp-setup-error', errorOf(r)); $('totp-setup').focus(); return; }
        setFormError('totp-setup-error', '');
        drawQr(r.body.qr);
        $('totp-key').textContent = String(r.body.secret).replace(/(.{4})/g, '$1 ').trim();
        $('totp-setup-box').hidden = false;
        $('totp-off').hidden = true;
        setFormError('totp-enable-error', '', ['totp-enable-code']);
        $('totp-enable-code').value = '';
        $('totp-enable-code').focus();
      });
    });
  });

  $('totp-key-copy').addEventListener('click', function () {
    copyText($('totp-key').textContent.replace(/\s+/g, ''), 'The key is copied.');
  });

  function endSetup() {
    $('totp-setup-box').hidden = true;
    $('totp-qr').textContent = '';
    $('totp-key').textContent = '';
  }

  $('totp-cancel').addEventListener('click', function () {
    endSetup();
    paint();
    $('totp-setup').focus();
  });

  $('totp-enable-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var input = $('totp-enable-code');
    var code = input.value.replace(/\s+/g, '');
    if (!/^[0-9]{6}$/.test(code)) { setFormError('totp-enable-error', 'Enter the 6 digits your app shows.', ['totp-enable-code']); input.focus(); return; }
    busy($('totp-enable'), 'Checking...', function () {
      return send('/api/account/totp/enable', { code: code }).then(function (r) {
        if (!r) return;
        if (r.status === 200) {
          endSetup();
          say('The app code is on. You are signed out everywhere else.');
          var codes = Array.isArray(r.body.recoveryCodes) ? r.body.recoveryCodes : null;
          if (!codes) { return load(); }
          data.totp = { enabled: true, recoveryCodesLeft: codes.length };
          data.secondFactor = true;
          data.recoveryCodesLeft = codes.length;
          showCodes(codes);
          paint();
          return;
        }
        setFormError('totp-enable-error', errorOf(r), ['totp-enable-code']);
        input.value = '';
        input.focus();
      });
    });
  });

  $('codes-copy').addEventListener('click', function () { copyText(codesText(), 'The recovery codes are copied.'); });

  $('codes-download').addEventListener('click', function () {
    var blob = new Blob([codesText()], { type: 'text/plain' });
    var a = el('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'recovery-codes.txt';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });

  $('codes-done').addEventListener('click', function () {
    $('codes-list').textContent = '';
    $('codes-box').hidden = true;
    load().then(function () { $('codes-new').focus(); });
  });

  $('codes-new-form').addEventListener('submit', function (e) {
    e.preventDefault();
    busy($('codes-new'), 'Making codes...', function () {
      return confirmed('/api/account/recovery-codes', {}, { title: 'Make new recovery codes', why: 'New codes take the place of all your old ones, which stop working.', action: 'Make new codes' }).then(function (r) {
        if (!r) return;
        if (r.status !== 200) { setFormError('codes-new-error', errorOf(r)); $('codes-new').focus(); return; }
        setFormError('codes-new-error', '');
        say('New recovery codes are made. The old ones no longer work.');
        showCodes(r.body.recoveryCodes);
      });
    });
  });

  $('totp-disable-form').addEventListener('submit', function (e) {
    e.preventDefault();
    busy($('totp-disable'), 'Turning off...', function () {
      return confirmed('/api/account/totp/disable', {}, { title: 'Turn off the app code', why: passkeyList().length > 0 ? 'The code from your app no longer signs you in. Your passkeys and recovery codes still work. You are signed out everywhere else.' : 'Your password alone will sign you in, your recovery codes stop working, and you are signed out everywhere else.', action: 'Turn off', danger: true }).then(function (r) {
        if (!r) return;
        if (r.status === 200) {
          setFormError('totp-disable-error', '');
          return load().then(function () {
            say(secondFactorOn() ? 'The app code is off. You are signed out everywhere else.' : 'Two-step sign-in is off. You are signed out everywhere else.');
            $('totp-setup').focus();
          });
        }
        setFormError('totp-disable-error', errorOf(r));
        $('totp-disable').focus();
      });
    });
  });

  // ---- passkeys ----
  function nameProblem(name) {
    return Array.from(name).length > 64 || CONTROL.test(name) ? 'Give the passkey a name of up to 64 characters.' : '';
  }

  function whyNotCreated(err) {
    if (window.rettuiPasskey.cancelled(err)) return 'The passkey was not added. Try again when you are ready.';
    if (err && err.name === 'InvalidStateError') return 'This passkey is added already.';
    return 'The passkey could not be made on this device. Try another one.';
  }

  $('passkey-add-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var input = $('passkey-name');
    var name = input.value.trim();
    var problem = nameProblem(name);
    if (problem) { setFormError('passkey-add-error', problem, ['passkey-name']); input.focus(); return; }
    if (!canPasskey()) { setFormError('passkey-add-error', 'This browser cannot make passkeys.', ['passkey-name']); return; }
    setFormError('passkey-add-error', '', ['passkey-name']);
    busy($('passkey-add'), 'Adding...', function () {
      return confirmed('/api/account/passkeys/begin', {}, { title: 'Add a passkey', why: 'Next your device asks you to make the passkey.', action: 'Continue' }).then(function (r) {
        if (!r) return;
        if (r.status !== 200 || !r.body || !r.body.options) { setFormError('passkey-add-error', errorOf(r)); input.focus(); return; }
        return window.rettuiPasskey.create(r.body.options).then(function (credential) {
          var body = { credential: credential };
          if (name) body.name = name;
          return send('/api/account/passkeys/finish', body).then(function (done) { return added(done, input); });
        }, function (err) {
          setFormError('passkey-add-error', whyNotCreated(err));
          input.focus();
        });
      });
    });
  });

  function added(r, input) {
    if (!r) return;
    if (r.status !== 200) {
      setFormError('passkey-add-error', errorOf(r), r.body && r.body.field === 'name' ? ['passkey-name'] : []);
      input.focus();
      return;
    }
    input.value = '';
    setFormError('passkey-add-error', '', ['passkey-name']);
    // The recovery codes come with the first second step only; that also signs the other sessions out.
    var codes = Array.isArray(r.body.recoveryCodes) && r.body.recoveryCodes.length > 0 ? r.body.recoveryCodes : null;
    return load().then(function () {
      say(codes ? 'The passkey is added. You are signed out everywhere else. Save your recovery codes now.' : 'The passkey is added.');
      if (codes) showCodes(codes);
      else $('acct-passkeys-h').focus();
    });
  }

  function removePasskey(button, pk) {
    var last = passkeyList().length + (data.totp && data.totp.enabled ? 1 : 0) <= 1;
    busy(button, 'Removing...', function () {
      return confirmed('/api/account/passkeys/remove', { id: pk.id }, {
        title: 'Remove the passkey ' + pk.name,
        why: last
          ? 'This is your only second step, so two-step sign-in turns off: your password alone will sign you in, your recovery codes stop working, and you are signed out everywhere else.'
          : 'You are signed out everywhere else. Your other ways to confirm keep working.',
        action: 'Remove',
        danger: true
      }).then(function (r) {
        if (!r) return;
        if (r.status !== 200) { say(errorOf(r)); return; }
        return load().then(function () {
          say(r.body.secondFactorOff ? 'The passkey is removed. Two-step sign-in is now off. You are signed out everywhere else.' : 'The passkey is removed. You are signed out everywhere else.');
          $('acct-passkeys-h').focus();
        });
      });
    });
  }

  // Rename in place: the item turns into a small form, and goes back when it is saved or given up.
  function startRename(li, pk) {
    var form = el('form', 'acct-form');
    form.noValidate = true;
    var err = el('p', 'login-error');
    err.setAttribute('role', 'alert');
    var label = el('label', null, 'New name for the passkey ' + pk.name);
    var input = el('input');
    input.type = 'text';
    input.value = pk.name;
    input.maxLength = 64;
    input.autocomplete = 'off';
    input.spellcheck = false;
    ['data-bwignore', 'data-1p-ignore', 'data-lpignore'].forEach(function (a) { input.setAttribute(a, 'true'); });
    input.id = 'passkey-rename-input';
    label.htmlFor = input.id;
    var actions = el('div', 'login-actions');
    var save = el('button', 'primary', 'Save name');
    save.type = 'submit';
    var cancel = el('button', null, 'Cancel');
    cancel.type = 'button';
    actions.appendChild(save);
    actions.appendChild(cancel);
    [err, label, input, actions].forEach(function (x) { form.appendChild(x); });
    li.textContent = '';
    li.appendChild(form);
    input.focus();
    function back() {
      shown.passkeys = null;
      paintPasskeys();
      if (passkeyButtons[pk.id]) passkeyButtons[pk.id].rename.focus();
    }
    cancel.addEventListener('click', back);
    input.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') back(); });
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var name = input.value.trim();
      var problem = name ? nameProblem(name) : 'Give the passkey a name of up to 64 characters.';
      if (problem) { err.textContent = problem; input.setAttribute('aria-invalid', 'true'); input.focus(); return; }
      if (name === pk.name) { back(); return; }
      busy(save, 'Saving...', function () {
        return send('/api/account/passkeys/rename', { id: pk.id, name: name }).then(function (r) {
          if (!r) return;
          if (r.status !== 200) { err.textContent = errorOf(r); input.setAttribute('aria-invalid', 'true'); input.focus(); return; }
          // The form goes, whatever the list says now.
          shown.passkeys = null;
          return load().then(function () {
            say('The passkey is renamed.');
            if (passkeyButtons[pk.id]) passkeyButtons[pk.id].rename.focus();
          });
        });
      });
    });
  }

  // ---- LXMF alerts ----
  var LXMF_ADDRESS = /^<?\s*[0-9a-fA-F]{32}\s*>?$/;
  // The address the next paint picks in the list of those that wait for a code (the one just added or sent to).
  var wanted = null;

  $('lxmf-set-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var input = $('lxmf-address');
    var address = input.value.trim();
    if (!LXMF_ADDRESS.test(address)) { setFormError('lxmf-set-error', 'An LXMF address is 32 hex digits, such as 0123456789abcdef0123456789abcdef.', ['lxmf-address']); input.focus(); return; }
    setFormError('lxmf-set-error', '', ['lxmf-address']);
    busy($('lxmf-set'), 'Sending...', function () {
      // Like adding a passkey: the step-up dialog asks for the password, and for the second step when one is on.
      return confirmed('/api/account/lxmf/set', { address: address }, { title: 'Add an LXMF address', why: 'A code is sent to the address next, and you type it back to confirm it. Your other confirmed addresses are told that it was added.', action: 'Send a code' }).then(function (r) {
        if (!r) return;
        if (r.status !== 200) { setFormError('lxmf-set-error', errorOf(r), r.body && r.body.field === 'address' ? ['lxmf-address'] : []); input.focus(); return; }
        input.value = '';
        wanted = r.body && typeof r.body.address === 'string' ? r.body.address : null;
        return load().then(function () {
          say('A code was sent to your LXMF address. Type it below to confirm the address.');
          $('lxmf-code').focus();
        });
      });
    });
  });

  $('lxmf-code-for').addEventListener('change', function () {
    setFormError('lxmf-confirm-error', '', ['lxmf-code']);
    paintCodeHelp();
  });

  $('lxmf-confirm-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var input = $('lxmf-code');
    var code = input.value.replace(/\s+/g, '');
    if (!/^[0-9]{6}$/.test(code)) { setFormError('lxmf-confirm-error', 'Enter the 6 digits that were sent to your LXMF address.', ['lxmf-code']); input.focus(); return; }
    setFormError('lxmf-confirm-error', '', ['lxmf-code']);
    busy($('lxmf-confirm'), 'Checking...', function () {
      return confirmed('/api/account/lxmf/confirm', { address: $('lxmf-code-for').value, lxmfCode: code }, { title: 'Confirm an LXMF address', why: 'Once confirmed, this address gets the alerts about your account.', action: 'Confirm the address' }).then(function (r) {
        if (!r) return;
        if (r.status !== 200) { setFormError('lxmf-confirm-error', errorOf(r), r.body && r.body.field === 'lxmfCode' ? ['lxmf-code'] : []); input.value = ''; input.focus(); return; }
        input.value = '';
        return load().then(function () {
          say('Your LXMF address is confirmed. Alerts about your account now go there.');
          $('acct-lxmf-h').focus();
        });
      });
    });
  });

  $('lxmf-resend').addEventListener('click', function () {
    var address = $('lxmf-code-for').value;
    busy($('lxmf-resend'), 'Sending...', function () {
      return send('/api/account/lxmf/resend', { address: address }).then(function (r) {
        if (!r) return;
        if (r.status !== 200) { setFormError('lxmf-confirm-error', errorOf(r), []); return; }
        setFormError('lxmf-confirm-error', '', ['lxmf-code']);
        wanted = address;
        return load().then(function () {
          say('A new code was sent to your LXMF address. The old one no longer works.');
          $('lxmf-code').focus();
        });
      });
    });
  });

  function removeLxmf(button, address) {
    busy(button, 'Removing...', function () {
      return confirmed('/api/account/lxmf/remove', { address: address }, { title: 'Remove an LXMF address', why: 'It gets no more alerts. Your other confirmed addresses are told that it was removed.', action: 'Remove', danger: true }).then(function (r) {
        if (!r) return;
        if (r.status !== 200) { say(errorOf(r)); return; }
        return load().then(function () {
          say('The LXMF address is removed. No more alerts go there.');
          $('acct-lxmf-h').focus();
        });
      });
    });
  }

  // What the answer to a test alert says: how many addresses the bridge was given the message for, and for those
  // held back by a limit, when they can go. It says the bridge was given the message: LXMF is slow and the website cannot tell more.
  function testWords(body) {
    var results = body && Array.isArray(body.results) ? body.results : [];
    var sent = results.filter(function (x) { return x && x.queued === true; }).length;
    var held = results.filter(function (x) { return x && x.queued !== true; });
    var noun = function (n) { return n + (n === 1 ? ' address' : ' addresses'); };
    var text = 'Sent to the bridge for ' + noun(sent) + '. LXMF can take a while to arrive.';
    if (held.length > 0) {
      var wait = Math.min.apply(null, held.map(function (x) { return typeof x.retryAfter === 'number' ? x.retryAfter : 3600; }));
      text += ' ' + noun(held.length) + (held.length === 1 ? ' was' : ' were') + ' held back by a limit; try again in ' + (wait < 90 ? Math.max(1, wait) + ' seconds' : Math.ceil(wait / 60) + ' minutes') + '.';
    }
    return text;
  }

  $('lxmf-test').addEventListener('click', function () {
    var result = $('lxmf-test-result');
    busy($('lxmf-test'), 'Sending...', function () {
      setText(result, '');
      return send('/api/account/lxmf/test', {}).then(function (r) {
        if (!r) return;
        setText(result, r.status === 200 ? testWords(r.body) : errorOf(r));
      });
    });
  });

  $('lxmf-nodes').addEventListener('change', function () {
    var box = $('lxmf-nodes');
    var on = box.checked;
    var told = '';
    var statusLine = $('lxmf-nodes-status');
    setText(statusLine, '');
    box.disabled = true;
    send('/api/account/lxmf/node-alerts', { enabled: on }).then(function (r) {
      if (!r) return;
      if (r.status !== 200) { setFormError('lxmf-nodes-error', errorOf(r), []); return; }
      setFormError('lxmf-nodes-error', '', []);
      told = on ? 'Node down and recovered alerts now go to your confirmed LXMF addresses too.' : 'Node alerts no longer go to your LXMF addresses.';
    }).catch(function () { told = 'Could not reach the server. Try again.'; }).then(function () {
      // Shows what the server has, whatever happened; load() clears the status line, so it is said after.
      return load();
    }).then(function () {
      box.disabled = false;
      if (told) setText(statusLine, told);
      box.focus();
    });
  });

  // ---- sessions ----
  $('sessions-end').addEventListener('click', function () {
    var button = this;
    busy(button, 'Signing out...', function () {
      return send('/api/account/sign-out-others', {}).then(function (r) {
        if (!r) return;
        if (r.status !== 200) { say(errorOf(r)); return; }
        say(r.body.ended === 1 ? 'One other session is signed out.' : r.body.ended + ' other sessions are signed out.');
        return load().then(function () { $('acct-sessions-h').focus(); });
      });
    });
  });

  // ---- known devices ----
  $('devices-others').addEventListener('click', function () {
    var button = this;
    busy(button, 'Removing...', function () {
      return send('/api/account/devices/remove-others', {}).then(function (r) {
        if (!r) return;
        if (r.status !== 200) { say(errorOf(r)); return; }
        say(r.body.removed === 1 ? 'One other device is removed and signed out.' : r.body.removed + ' other devices are removed and signed out.');
        return load().then(function () { $('acct-devices-h').focus(); });
      });
    });
  });

  $('acct-signin-btn').addEventListener('click', function () {
    var button = this;
    if (window.rettuiAccount) window.rettuiAccount.open(button, function () { load().then(function () { $('main').focus(); }); });
  });

  // Signing in or out in the header changes what this page shows.
  function hook() {
    if (!window.rettuiAccount || hook.done) return;
    hook.done = true;
    window.rettuiAccount.onChange(function () { return load(); });
  }
  document.addEventListener('rettui:account', hook);
  hook();
  load();
})();
