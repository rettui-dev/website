// The sign in button in the header, on every page, and the sign in dialog it opens. Without users in
// the config file the server says so (GET /api/session) and the button stays hidden. Signing in and
// out are the same POST /login and /logout the status page has always used; the page stays where it
// is, so the visitor is back on it as soon as the dialog closes. The status page asks for the dialog
// too (window.rettuiAccount.open) and reloads its numbers when the viewer changes.
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
    nameEl.textContent = name || '';
    if (name) nameEl.title = name;
    else nameEl.removeAttribute('title');
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
    fetch('/login', { method: 'POST', body: new URLSearchParams({ name: user.value, password: pass.value }), credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (body) { return { status: r.status, body: body }; });
      })
      .then(function (r) {
        if (r.status === 200 && r.body.ok) {
          ok = true;
          pass.value = '';
          name = typeof r.body.name === 'string' ? r.body.name : null;
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
        setError(r.body && r.body.error ? r.body.error : 'Could not sign in. Try again.');
      })
      .catch(function () { setError('Could not reach the server. Try again.'); })
      .then(function () {
        busy = false;
        button.disabled = false;
        button.textContent = 'Sign in';
        if (!ok && dlg.open) {
          pass.value = '';
          pass.focus();
        }
      });
  }

  function signOut() {
    fetch('/logout', { method: 'POST', body: new URLSearchParams(), credentials: 'same-origin', cache: 'no-store' })
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
    document.body.appendChild(dlg);
    form.addEventListener('submit', submit);
    cancel.addEventListener('click', function () { dlg.close(); });
    dlg.addEventListener('click', function (e) { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener('close', function () {
      var back = opener;
      opener = null;
      afterSignIn = null;
      if (back) refocus(back);
    });
  }

  // Opens the dialog. back gets the focus again if the visitor gives up; then() runs after a sign in
  // (the focus is then up to it).
  function open(back, then) {
    if (!enabled || !dlg) return;
    opener = back || btn;
    afterSignIn = then || null;
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
