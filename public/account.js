// The sign in button in the header, on every page, and the sign in dialog it opens. Without users
// the server says so (GET /api/session) and the button stays hidden. Signing in and out are the same
// POST /login and /logout the status page has always used; the page stays where it is, so the visitor
// is back on it as soon as the dialog closes. A user with two-step sign-in gets a second step in the
// same dialog: the code from their app, or a recovery code (POST /login/code). Signed in, the name in
// the header links to the account page. The status page asks for the dialog too
// (window.rettuiAccount.open) and reloads its numbers when the viewer changes.
(function () {
  'use strict';
  var box = document.getElementById('signin');
  var btn = document.getElementById('signin-btn');
  var nameEl = document.getElementById('signin-name');
  if (!box || !btn || !nameEl) return;

  var enabled = false;
  var name = null;
  var dlg = null;
  var opener = null;
  var afterSignIn = null;
  var busy = false;
  var listeners = [];
  // The token of the second step, while the dialog asks for a code; and whether it asks for a recovery code.
  var pending = null;
  var useRecovery = false;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  // Spoken, not shown: the buttons change in place, so a screen reader is told.
  var live = el('p', 'sr-only');
  live.id = 'account-live';
  live.setAttribute('role', 'status');
  document.body.appendChild(live);

  function paint() {
    box.hidden = !enabled;
    if (!enabled) return;
    nameEl.hidden = !name;
    nameEl.textContent = '';
    if (name) {
      // The name is the way to the account page.
      var link = el('a', 'signin-link', name);
      link.href = '/account';
      link.title = name;
      if (location.pathname === '/account' || location.pathname === '/account/') link.setAttribute('aria-current', 'page');
      nameEl.appendChild(link);
    }
    btn.textContent = name ? 'Sign out' : 'Sign in';
    // The name starts with the visible words, so voice control can say what it sees.
    if (name) btn.setAttribute('aria-label', 'Sign out ' + name);
    else btn.setAttribute('aria-label', 'Sign in');
    btn.setAttribute('data-state', name ? 'in' : 'out');
  }

  // Tells whoever listens (the status page) that the viewer changed; they may return a promise.
  function changed() {
    return Promise.all(listeners.map(function (fn) {
      try { return fn(name); } catch (e) { return null; }
    }));
  }

  function refocus(back) {
    if (back && back.isConnected && back.offsetParent !== null) back.focus();
    else if (btn.offsetParent !== null) btn.focus();
  }

  function setError(text) {
    var e = document.getElementById('login-error');
    e.textContent = text;
    var bad = text ? 'true' : 'false';
    document.getElementById('login-name').setAttribute('aria-invalid', bad);
    document.getElementById('login-password').setAttribute('aria-invalid', bad);
  }

  function setCodeError(text) {
    document.getElementById('login-code-error').textContent = text;
    var bad = text ? 'true' : 'false';
    document.getElementById('login-code').setAttribute('aria-invalid', bad);
    document.getElementById('login-recovery').setAttribute('aria-invalid', bad);
  }

  // The server only takes these with the X-Rettui-Request header, which a form on another site cannot send.
  function post(path, fields) {
    return fetch(path, { method: 'POST', body: new URLSearchParams(fields), headers: { 'X-Rettui-Request': '1' }, credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (body) { return { status: r.status, body: body }; });
      });
  }

  // The dialog shows one step at a time: the password, or the code.
  function showStep(codeStep) {
    document.getElementById('login-form').hidden = codeStep;
    document.getElementById('login-code-form').hidden = !codeStep;
    dlg.setAttribute('aria-labelledby', codeStep ? 'login-code-title' : 'login-title');
    if (!codeStep) {
      pending = null;
      setRecovery(false);
    }
  }

  function setRecovery(on) {
    useRecovery = on;
    var code = document.getElementById('login-code');
    var rec = document.getElementById('login-recovery');
    code.value = '';
    rec.value = '';
    document.getElementById('login-code-label').hidden = on;
    code.hidden = on;
    document.getElementById('login-recovery-label').hidden = !on;
    rec.hidden = !on;
    document.getElementById('login-code-why').textContent = on
      ? 'Enter one of your recovery codes. Each one works once.'
      : 'Enter the 6-digit code from your authenticator app.';
    document.getElementById('login-use-recovery').textContent = on ? 'Use the code from the app' : 'Use a recovery code';
    setCodeError('');
  }

  // A sign in that is complete: the dialog closes and whoever listens hears of it.
  function signedIn(body) {
    var pass = document.getElementById('login-password');
    pass.value = '';
    name = typeof body.name === 'string' ? body.name : null;
    var then = afterSignIn;
    var back = opener;
    afterSignIn = null;
    opener = null;
    dlg.close();
    paint();
    live.textContent = 'Signed in as ' + name + '.';
    return changed().then(function () {
      if (then) then();
      else refocus(back);
    });
  }

  function submit(e) {
    e.preventDefault();
    if (busy) return;
    var user = document.getElementById('login-name');
    var pass = document.getElementById('login-password');
    if (!user.value.trim() || !pass.value) {
      setError('Enter your name and password.');
      (user.value.trim() ? pass : user).focus();
      return;
    }
    var button = document.getElementById('login-submit');
    busy = true;
    button.disabled = true;
    button.textContent = 'Signing in...';
    setError('');
    var ok = false;
    var second = false;
    post('/login', { name: user.value, password: pass.value })
      .then(function (r) {
        if (r.status === 200 && r.body.ok) {
          ok = true;
          return signedIn(r.body);
        }
        if (r.status === 200 && r.body.secondFactor && typeof r.body.pending === 'string') {
          second = true;
          pass.value = '';
          pending = r.body.pending;
          showStep(true);
          setRecovery(false);
          // Wrong codes hold the code step back for a while: the server says how long.
          if (typeof r.body.notice === 'string') setCodeError(r.body.notice);
          document.getElementById('login-code').focus();
          return null;
        }
        setError(r.body && r.body.error ? r.body.error : 'Could not sign in. Try again.');
        return null;
      })
      .catch(function () { setError('Could not reach the server. Try again.'); })
      .then(function () {
        busy = false;
        button.disabled = false;
        button.textContent = 'Sign in';
        if (!ok && !second && dlg.open) {
          pass.value = '';
          pass.focus();
        }
      });
  }

  function submitCode(e) {
    e.preventDefault();
    if (busy) return;
    var input = document.getElementById(useRecovery ? 'login-recovery' : 'login-code');
    var value = input.value.replace(/\s+/g, '');
    if (!useRecovery && !/^[0-9]{6}$/.test(value)) {
      setCodeError('Enter the 6 digits your app shows.');
      input.focus();
      return;
    }
    if (useRecovery && !value) {
      setCodeError('Enter a recovery code.');
      input.focus();
      return;
    }
    var button = document.getElementById('login-code-submit');
    busy = true;
    button.disabled = true;
    button.textContent = 'Checking...';
    setCodeError('');
    var fields = { pending: pending || '' };
    fields[useRecovery ? 'recovery' : 'code'] = value;
    var ok = false;
    post('/login/code', fields)
      .then(function (r) {
        if (r.status === 200 && r.body.ok) {
          ok = true;
          return signedIn(r.body);
        }
        var text = r.body && r.body.error ? r.body.error : 'Could not sign in. Try again.';
        if (r.body && r.body.restart) {
          // The second step is over: back to the name and password.
          showStep(false);
          setError(text);
          document.getElementById('login-password').focus();
          return null;
        }
        setCodeError(text);
        return null;
      })
      .catch(function () { setCodeError('Could not reach the server. Try again.'); })
      .then(function () {
        busy = false;
        button.disabled = false;
        button.textContent = 'Sign in';
        if (!ok && dlg.open && pending) {
          input.value = '';
          input.focus();
        }
      });
  }

  function signOut() {
    post('/logout', {})
      .then(function () {
        name = null;
        paint();
        live.textContent = 'Signed out.';
        return changed();
      })
      .then(function () { refocus(null); })
      .catch(function () { live.textContent = 'Could not sign out. Try again.'; });
  }

  function build() {
    dlg = el('dialog', 'login');
    dlg.id = 'login';
    dlg.setAttribute('aria-labelledby', 'login-title');
    var form = el('form', 'login-form');
    form.id = 'login-form';
    form.method = 'post';
    form.action = '/login';
    form.noValidate = true;
    var title = el('h2', null, 'Sign in');
    title.id = 'login-title';
    form.appendChild(title);
    form.appendChild(el('p', 'note login-why', 'Some details are only shown to signed-in users.'));
    var err = el('p', 'login-error');
    err.id = 'login-error';
    err.setAttribute('role', 'alert');
    form.appendChild(err);
    [['login-name', 'name', 'Name', 'text', 'username', 64], ['login-password', 'password', 'Password', 'password', 'current-password', 1024]].forEach(function (f) {
      var label = el('label', null, f[2]);
      label.htmlFor = f[0];
      var input = el('input');
      input.id = f[0];
      input.name = f[1];
      input.type = f[3];
      input.autocomplete = f[4];
      input.maxLength = f[5];
      input.required = true;
      input.setAttribute('aria-describedby', 'login-error');
      if (f[3] === 'text') {
        input.setAttribute('autocapitalize', 'none');
        input.spellcheck = false;
      }
      form.appendChild(label);
      form.appendChild(input);
    });
    var actions = el('div', 'login-actions');
    var go = el('button', 'primary', 'Sign in');
    go.id = 'login-submit';
    go.type = 'submit';
    var cancel = el('button', null, 'Cancel');
    cancel.id = 'login-cancel';
    cancel.type = 'button';
    actions.appendChild(go);
    actions.appendChild(cancel);
    form.appendChild(actions);
    dlg.appendChild(form);
    dlg.appendChild(buildCodeForm());
    document.body.appendChild(dlg);
    form.addEventListener('submit', submit);
    cancel.addEventListener('click', function () { dlg.close(); });
    dlg.addEventListener('click', function (e) { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener('close', function () {
      showStep(false);
      var back = opener;
      opener = null;
      afterSignIn = null;
      if (back) refocus(back);
    });
  }

  // The second step: a code from the app, or a recovery code instead.
  function buildCodeForm() {
    var form = el('form', 'login-form');
    form.id = 'login-code-form';
    form.method = 'post';
    form.action = '/login/code';
    form.noValidate = true;
    form.hidden = true;
    var title = el('h2', null, 'Two-step sign-in');
    title.id = 'login-code-title';
    form.appendChild(title);
    var why = el('p', 'note login-why', 'Enter the 6-digit code from your authenticator app.');
    why.id = 'login-code-why';
    form.appendChild(why);
    var err = el('p', 'login-error');
    err.id = 'login-code-error';
    err.setAttribute('role', 'alert');
    form.appendChild(err);
    var label = el('label', null, 'Code');
    label.id = 'login-code-label';
    label.htmlFor = 'login-code';
    var code = el('input');
    code.id = 'login-code';
    code.name = 'code';
    code.type = 'text';
    code.setAttribute('inputmode', 'numeric');
    code.autocomplete = 'one-time-code';
    code.pattern = '[0-9]{6}';
    code.maxLength = 6;
    code.required = true;
    code.setAttribute('aria-describedby', 'login-code-why login-code-error');
    var recLabel = el('label', null, 'Recovery code');
    recLabel.id = 'login-recovery-label';
    recLabel.htmlFor = 'login-recovery';
    recLabel.hidden = true;
    var rec = el('input');
    rec.id = 'login-recovery';
    rec.name = 'recovery';
    rec.type = 'text';
    rec.autocomplete = 'off';
    rec.maxLength = 32;
    rec.hidden = true;
    rec.spellcheck = false;
    rec.setAttribute('autocapitalize', 'none');
    rec.setAttribute('aria-describedby', 'login-code-why login-code-error');
    [label, code, recLabel, rec].forEach(function (x) { form.appendChild(x); });
    var swap = el('button', 'link-btn login-swap', 'Use a recovery code');
    swap.id = 'login-use-recovery';
    swap.type = 'button';
    swap.addEventListener('click', function () {
      setRecovery(!useRecovery);
      document.getElementById(useRecovery ? 'login-recovery' : 'login-code').focus();
    });
    form.appendChild(swap);
    var actions = el('div', 'login-actions');
    var go = el('button', 'primary', 'Sign in');
    go.id = 'login-code-submit';
    go.type = 'submit';
    var cancel = el('button', null, 'Cancel');
    cancel.type = 'button';
    cancel.addEventListener('click', function () { dlg.close(); });
    actions.appendChild(go);
    actions.appendChild(cancel);
    form.appendChild(actions);
    form.addEventListener('submit', submitCode);
    return form;
  }

  // Opens the dialog. back gets the focus again if the visitor gives up; then() runs after a sign in
  // (the focus is then up to it).
  function open(back, then) {
    if (!enabled || !dlg) return;
    opener = back || btn;
    afterSignIn = then || null;
    showStep(false);
    setError('');
    document.getElementById('login-password').value = '';
    if (!dlg.open) dlg.showModal();
    var user = document.getElementById('login-name');
    (user.value ? document.getElementById('login-password') : user).focus();
  }

  btn.addEventListener('click', function () {
    if (name) signOut();
    else open(btn, null);
  });

  window.rettuiAccount = {
    open: open,
    // The name of whoever is signed in, or null.
    name: function () { return name; },
    // Whether this site has users at all.
    enabled: function () { return enabled; },
    // For the status page, whose own answers say who is signed in (a session may have ended).
    sync: function (viewerName) {
      var next = typeof viewerName === 'string' ? viewerName : null;
      if (!enabled || next === name) return;
      name = next;
      paint();
    },
    onChange: function (fn) { listeners.push(fn); }
  };

  if (typeof HTMLDialogElement === 'undefined' || typeof document.createElement('dialog').showModal !== 'function') return;
  fetch('/api/session', { cache: 'no-store', credentials: 'same-origin' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (s) {
      if (!s || s.enabled !== true) return;
      enabled = true;
      name = typeof s.name === 'string' ? s.name : null;
      build();
      paint();
      document.dispatchEvent(new CustomEvent('rettui:account'));
    })
    .catch(function () { /* the button stays hidden */ });
})();
