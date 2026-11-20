// The step-up dialog: before a sensitive change (a password change, new recovery codes, turning
// two-step sign-in off, adding or removing a passkey, the changes on the users page) it asks for the
// password, and when a second step is on, for a passkey, a code from the app or a recovery code as
// well. The server asks for both too; this only collects them. One modal dialog, built here (no inline script), with the focus
// kept inside it, Escape to close, and the focus given back to whatever opened it.
//
// window.rettuiStepUp.ask({title, why, action, secondFactor, methods, send}) opens it. methods is
// what the server says can confirm for this user (a list of 'passkey', 'totp', 'recovery'); without
// it secondFactor true means the app code and the recovery code. With a passkey the dialog gets a
// challenge from the server (POST /api/account/passkeys/challenge) when the visitor presses Confirm,
// asks the browser for the passkey, and sends it. send(fields) gets {password} or {password, code}
// or {password, recovery} or {password, passkey}, and gives a promise of the answer
// ({status, body}) or null. A wrong password or code (an answer of 400 with a field, or a 429)
// is shown in the dialog, which stays open; anything else closes it, and ask() resolves with the
// answer (null when the visitor gave up).
(function () {
  'use strict';
  var dlg = null;
  var state = null;
  // Said by a step that has shown its own error and ends the attempt (a null answer is the page giving up).
  var STOP = {};

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function $(id) { return document.getElementById(id); }

  // A text field that password managers leave alone (they take a lone text field for a name).
  function codeInput(id, max) {
    var i = el('input');
    i.id = id;
    i.type = 'text';
    i.autocomplete = id === 'stepup-code' ? 'one-time-code' : 'off';
    i.maxLength = max;
    i.spellcheck = false;
    i.setAttribute('autocapitalize', 'none');
    ['data-bwignore', 'data-1p-ignore', 'data-lpignore'].forEach(function (a) { i.setAttribute(a, 'true'); });
    i.setAttribute('aria-describedby', 'stepup-why stepup-error');
    return i;
  }

  function build() {
    dlg = el('dialog', 'login');
    dlg.id = 'stepup';
    dlg.setAttribute('aria-labelledby', 'stepup-title');
    dlg.setAttribute('aria-describedby', 'stepup-why');
    var form = el('form', 'login-form');
    form.id = 'stepup-form';
    form.noValidate = true;
    var title = el('h2', null, 'Confirm it is you');
    title.id = 'stepup-title';
    var why = el('p', 'note login-why');
    why.id = 'stepup-why';
    var err = el('p', 'login-error');
    err.id = 'stepup-error';
    err.setAttribute('role', 'alert');
    err.setAttribute('aria-live', 'assertive');
    var pwLabel = el('label', null, 'Your password');
    pwLabel.htmlFor = 'stepup-password';
    var pw = el('input');
    pw.id = 'stepup-password';
    pw.type = 'password';
    pw.autocomplete = 'current-password';
    pw.maxLength = 1024;
    pw.required = true;
    pw.setAttribute('aria-describedby', 'stepup-why stepup-error');
    var codeLabel = el('label', null, 'Code from your app');
    codeLabel.id = 'stepup-code-label';
    codeLabel.htmlFor = 'stepup-code';
    var code = codeInput('stepup-code', 6);
    code.setAttribute('inputmode', 'numeric');
    code.pattern = '[0-9]{6}';
    var recLabel = el('label', null, 'Recovery code');
    recLabel.id = 'stepup-recovery-label';
    recLabel.htmlFor = 'stepup-recovery';
    var rec = codeInput('stepup-recovery', 32);
    // One link for each other way to confirm; setMode shows the ones this user has.
    var swaps = [['stepup-use-passkey', 'Use your passkey instead', 'passkey'], ['stepup-use-code', 'Use the code from your app instead', 'code'], ['stepup-use-recovery', 'Use a recovery code instead', 'recovery']].map(function (x) {
      var b = el('button', 'link-btn login-swap', x[1]);
      b.id = x[0];
      b.type = 'button';
      b.addEventListener('click', function () {
        if (state.busy) return;
        setMode(x[2]);
        focusMode();
      });
      return b;
    });
    var actions = el('div', 'login-actions');
    var go = el('button', 'primary', 'Confirm');
    go.id = 'stepup-go';
    go.type = 'submit';
    var cancel = el('button', null, 'Cancel');
    cancel.id = 'stepup-cancel';
    cancel.type = 'button';
    actions.appendChild(go);
    actions.appendChild(cancel);
    [title, why, err, pwLabel, pw, codeLabel, code, recLabel, rec].concat(swaps, [actions]).forEach(function (x) { form.appendChild(x); });
    dlg.appendChild(form);
    document.body.appendChild(dlg);

    cancel.addEventListener('click', function () { dlg.close(); });
    // Escape closes it (the browser's cancel), and so does a click on the backdrop.
    dlg.addEventListener('click', function (e) { if (e.target === dlg && !state.busy) dlg.close(); });
    dlg.addEventListener('cancel', function (e) { if (state && state.busy) e.preventDefault(); });
    // The focus stays in the dialog: Tab from the last control goes to the first, and back.
    dlg.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab') return;
      var list = Array.prototype.filter.call(dlg.querySelectorAll('input, button'), function (x) { return !x.hidden && !x.disabled; });
      if (list.length === 0) return;
      var first = list[0];
      var last = list[list.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
    dlg.addEventListener('close', function () {
      var s = state;
      state = null;
      pw.value = code.value = rec.value = '';
      if (!s) return;
      if (s.back && s.back.isConnected) s.back.focus();
      s.resolve(s.answer);
    });
    form.addEventListener('submit', submit);
  }

  var WHY = {
    none: 'Enter your password.',
    passkey: 'Enter your password, then confirm with your passkey.',
    code: 'Enter your password and the code your app shows now.',
    recovery: 'Enter your password and a recovery code.'
  };

  function canPasskey() {
    return Boolean(window.rettuiPasskey) && window.rettuiPasskey.supported();
  }

  // Whether a way to confirm is on offer: the server lists it, and for a passkey the browser can do it.
  function offered(which) {
    if (!state.secondFactor) return false;
    if (which === 'passkey') return state.methods.indexOf('passkey') >= 0 && canPasskey();
    return state.methods.indexOf(which === 'code' ? 'totp' : 'recovery') >= 0;
  }

  function firstMode() {
    return ['passkey', 'code', 'recovery'].filter(offered)[0] || 'code';
  }

  // The dialog shows one way at a time: the passkey (no field), the code, or the recovery code.
  function setMode(which) {
    state.mode = which;
    var second = state.secondFactor;
    $('stepup-code-label').hidden = !second || which !== 'code';
    $('stepup-code').hidden = !second || which !== 'code';
    $('stepup-recovery-label').hidden = !second || which !== 'recovery';
    $('stepup-recovery').hidden = !second || which !== 'recovery';
    $('stepup-use-passkey').hidden = !offered('passkey') || which === 'passkey';
    $('stepup-use-code').hidden = !offered('code') || which === 'code';
    $('stepup-use-recovery').hidden = !offered('recovery') || which === 'recovery';
    $('stepup-code').value = '';
    $('stepup-recovery').value = '';
    var note = state.methods.indexOf('passkey') >= 0 && !canPasskey() ? ' This browser cannot use your passkey.' : '';
    $('stepup-why').textContent = (state.why ? state.why + ' ' : '') + WHY[second ? which : 'none'] + (second && which !== 'passkey' ? note : '');
    setError('', []);
  }

  function focusMode() {
    $(state.mode === 'recovery' ? 'stepup-recovery' : state.mode === 'code' ? 'stepup-code' : 'stepup-password').focus();
  }

  // Takes the list the server gave, or the app code and recovery code when it only said "a second step".
  function methodsOf(list, secondFactor) {
    if (Array.isArray(list)) return list.filter(function (m) { return m === 'passkey' || m === 'totp' || m === 'recovery'; });
    return secondFactor ? ['totp', 'recovery'] : [];
  }

  function setError(text, bad) {
    $('stepup-error').textContent = text;
    ['stepup-password', 'stepup-code', 'stepup-recovery'].forEach(function (id) { $(id).setAttribute('aria-invalid', bad.indexOf(id) >= 0 ? 'true' : 'false'); });
  }

  // A request of the same kind as the pages send: JSON with the X-Rettui-Request header.
  function post(path, body) {
    return fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-Rettui-Request': '1' },
      body: JSON.stringify(body)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) { return { status: r.status, body: b }; });
    });
  }

  // Asks the server for a challenge and the browser for the passkey. The server may want the password
  // first when the sign in is older than 15 minutes (the password given makes it recent again).
  // Gives {credential} or {fail: text, answer?}; answer is a reply the caller should see as it is.
  function passkeyAnswer(password) {
    return post('/api/account/passkeys/challenge', {}).then(function (c) {
      if (c.status !== 403 || !c.body.reauth) return c;
      return post('/api/account/reauth', { password: password }).then(function (a) {
        if (a.status !== 200) return { status: a.status, body: { field: 'password', error: a.body && a.body.error ? a.body.error : 'That did not work. Try again.' } };
        return post('/api/account/passkeys/challenge', {});
      });
    }).then(function (c) {
      if (c.status === 401 && c.body.signIn) return { answer: c };
      if (c.body && c.body.field === 'password') return { answer: c };
      if (c.status !== 200 || !c.body.options) return { fail: c.body && c.body.error ? c.body.error : 'The passkey could not be asked for. Try again, or use another way to confirm.' };
      return window.rettuiPasskey.get(c.body.options).then(function (credential) {
        return { credential: credential };
      }, function (err) {
        return { fail: window.rettuiPasskey.cancelled(err) ? 'The passkey was not used. Try again, or use another way to confirm.' : 'Could not use the passkey. Try again, or use another way to confirm.' };
      });
    });
  }

  function submit(e) {
    e.preventDefault();
    if (!state || state.busy) return;
    var pw = $('stepup-password');
    var fields = { password: pw.value };
    if (!pw.value) { setError('Enter your password.', ['stepup-password']); pw.focus(); return; }
    if (state.secondFactor && state.mode === 'code') {
      var c = $('stepup-code').value.replace(/\s+/g, '');
      if (!/^[0-9]{6}$/.test(c)) { setError('Enter the 6 digits your app shows.', ['stepup-code']); $('stepup-code').focus(); return; }
      fields.code = c;
    } else if (state.secondFactor && state.mode === 'recovery') {
      var r = $('stepup-recovery').value.trim();
      if (!r) { setError('Enter a recovery code.', ['stepup-recovery']); $('stepup-recovery').focus(); return; }
      fields.recovery = r;
    }
    var go = $('stepup-go');
    var label = go.textContent;
    var viaPasskey = state.secondFactor && state.mode === 'passkey';
    state.busy = true;
    go.disabled = true;
    if (viaPasskey) go.textContent = 'Waiting for your passkey...';
    setError('', []);
    var s = state;
    var refocus = null;
    (viaPasskey ? passkeyAnswer(fields.password) : Promise.resolve({})).then(function (p) {
      if (state !== s) return STOP;
      if (p.fail) { setError(p.fail, []); refocus = 'stepup-go'; return STOP; }
      if (p.answer) return p.answer;
      if (p.credential) fields.passkey = p.credential;
      return s.send(fields);
    }).then(function (answer) {
      if (state !== s || answer === STOP) return;
      var b = answer && answer.body ? answer.body : {};
      // A wrong password, code or passkey: said here, and the visitor tries again.
      if (answer && ((answer.status === 400 && (b.field === 'password' || b.field === 'code' || b.field === 'recovery' || b.field === 'passkey')) || answer.status === 429)) {
        var id = b.field === 'code' ? 'stepup-code' : b.field === 'recovery' ? 'stepup-recovery' : b.field === 'passkey' ? 'stepup-go' : 'stepup-password';
        // The server wants a second step this dialog did not know of yet, or other ways than it thought.
        if (b.secondFactor && !s.secondFactor) s.secondFactor = true;
        if (b.secondFactor || Array.isArray(b.methods)) {
          s.methods = methodsOf(b.methods, true);
          setMode(firstMode());
        }
        setError(b.error || 'That did not work. Try again.', id === 'stepup-go' ? [] : [id]);
        if (b.field !== 'password') { $('stepup-code').value = ''; $('stepup-recovery').value = ''; }
        refocus = id === 'stepup-code' && s.mode === 'recovery' ? 'stepup-recovery' : id;
        return;
      }
      s.answer = answer;
      dlg.close();
    }, function () {
      if (state === s) setError('Could not reach the server. Try again.', []);
    }).then(function () {
      s.busy = false;
      go.disabled = false;
      go.textContent = label;
      // A disabled button cannot take the focus, so this waits until it is back on.
      if (refocus && state === s) $(refocus).focus();
    });
  }

  window.rettuiStepUp = {
    // opts: {title, why, action, secondFactor, send}. Resolves with the answer, or null.
    ask: function (opts) {
      return new Promise(function (resolve) {
        if (!dlg) build();
        if (state) { resolve(null); return; }
        var methods = methodsOf(opts.methods, opts.secondFactor === true);
        state = { resolve: resolve, answer: null, busy: false, mode: 'code', why: opts.why || '', methods: methods, secondFactor: methods.length > 0, send: opts.send, back: document.activeElement };
        $('stepup-title').textContent = opts.title;
        $('stepup-go').textContent = opts.action || 'Confirm';
        $('stepup-go').className = opts.danger ? 'danger' : 'primary';
        setMode(firstMode());
        dlg.showModal();
        $('stepup-password').focus();
      });
    }
  };
})();
