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
    var why = el('p', 'note login-why', 'You signed in more than 15 minutes ago. Enter your password to go on.');
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
    $('acct-name').textContent = data.name;
    $('acct-role').textContent = data.role;
    $('acct-last').textContent = when(data.lastLogin);
    $('acct-config-note').hidden = !data.managedByConfig;
    $('acct-users').hidden = data.canManageUsers !== true;
    // A password an admin set: the password change is all there is until a new one is chosen.
    $('acct-must-change').hidden = data.mustChangePassword !== true;
    Array.prototype.forEach.call(document.querySelectorAll('[data-after-password]'), function (x) { x.hidden = data.mustChangePassword === true; });
    $('pw-config').hidden = data.canChangePassword;
    $('pw-form').hidden = !data.canChangePassword;
    // For password managers: the name the new password belongs to.
    $('pw-user').value = data.name;
    var on = Boolean(data.totp && data.totp.enabled);
    var keys = passkeyList().length;
    $('totp-state').textContent = on
      ? (keys > 0 ? 'On: after your password you can also use a code from your app.' : 'On: signing in needs your password and a code from your app.')
      : (keys > 0 ? 'Off: no app code is set up. Your passkeys are your second step.' : 'Off: your password alone signs you in.');
    $('totp-off').hidden = on || !$('totp-setup-box').hidden;
    $('sessions-end').hidden = data.sessions.length < 2;
    $('totp-on').hidden = !on;
    // Recovery codes belong to any second step, not just the app code.
    var left = typeof data.recoveryCodesLeft === 'number' ? data.recoveryCodesLeft : on && data.totp ? data.totp.recoveryCodesLeft : 0;
    $('codes-left').textContent = left === 1 ? '1 recovery code left.' : left + ' recovery codes left.';
    $('codes-on').hidden = !secondFactorOn() || !$('codes-box').hidden;
    var list = $('sessions-list');
    list.textContent = '';
    data.sessions.forEach(function (s) {
      var li = el('li');
      li.appendChild(el('span', null, 'Signed in ' + when(s.created) + ', last used ' + when(s.lastSeen)));
      if (s.current) li.appendChild(el('strong', 'acct-current', ' (this browser)'));
      list.appendChild(li);
    });
    // These are set after the loop above, which hides everything marked for after the password change.
    $('acct-passkeys').hidden = data.mustChangePassword === true || !data.passkeys;
    $('acct-recovery').hidden = data.mustChangePassword === true || !(secondFactorOn() || !$('codes-box').hidden);
    paintPasskeys();
    paintDevices();
  }

  // The passkeys: what the server lists, and what can be done here. A passkey made for another address
  // is listed, so it can be removed, but it cannot be used here.
  function paintPasskeys() {
    var p = data.passkeys;
    var list = $('passkeys-list');
    list.textContent = '';
    passkeyButtons = {};
    if (!p) return;
    var items = passkeyList();
    var max = typeof p.max === 'number' ? p.max : 10;
    var here = p.available === true;
    var browser = canPasskey();
    $('passkeys-unavailable').hidden = here;
    $('passkeys-unavailable').textContent = p.reason === 'no-address'
      ? "Passkeys need this site's https address in the config file (site.url, or SITE_URL)."
      : 'Passkeys are not available on this site.';
    $('passkeys-none').hidden = items.length > 0;
    $('passkeys-browser').hidden = !here || browser;
    var full = here && items.length >= max;
    $('passkeys-full').hidden = !full;
    $('passkeys-full').textContent = 'You have ' + items.length + ' passkeys, the most allowed. Remove one first.';
    $('passkey-add-form').hidden = !here || !browser || full;
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
    list.textContent = '';
    $('devices-none').hidden = devices.length > 0;
    var others = 0;
    devices.forEach(function (d) {
      var li = el('li');
      var label = 'First used ' + when(d.created) + ', last used ' + when(d.lastUsed);
      li.appendChild(el('span', null, label));
      if (d.current) li.appendChild(el('strong', 'acct-current', ' (this browser)'));
      else others++;
      var remove = el('button', null, 'Remove');
      remove.type = 'button';
      remove.setAttribute('aria-label', 'Remove the device ' + label.charAt(0).toLowerCase() + label.slice(1));
      remove.addEventListener('click', function () { removeDevice(remove, d.id); });
      li.appendChild(document.createTextNode(' '));
      li.appendChild(remove);
      list.appendChild(li);
    });
    $('devices-others').hidden = others === 0;
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
      return confirmed('/api/account/password', { next: next.value }, { title: 'Change your password', why: 'Your new password takes the place of the current one, and you are signed out everywhere else.', action: 'Change password' }).then(function (r) {
        if (!r) return;
        if (r.status === 200) {
          next.value = again.value = '';
          say('Your password is changed. You are signed out everywhere else.');
          return load();
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
          return load().then(function () {
            say('The passkey is renamed.');
            if (passkeyButtons[pk.id]) passkeyButtons[pk.id].rename.focus();
          });
        });
      });
    });
  }

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
