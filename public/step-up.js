// The step-up dialog: before a sensitive change (a password change, new recovery codes, turning
// two-step sign-in off, the changes on the users page) it asks for the password, and when two-step
// sign-in is on, for a code from the app (or a recovery code) as well. The server asks for both
// too; this only collects them. One modal dialog, built here (no inline script), with the focus
// kept inside it, Escape to close, and the focus given back to whatever opened it.
//
// window.rettuiStepUp.ask({title, why, action, secondFactor, send}) opens it. send(fields) gets
// {password} or {password, code} or {password, recovery}, and gives a promise of the answer
// ({status, body}) or null. A wrong password or code (an answer of 400 with a field, or a 429)
// is shown in the dialog, which stays open; anything else closes it, and ask() resolves with the
// answer (null when the visitor gave up).
(function () {
  'use strict';
  var dlg = null;
  var state = null;

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
    var swap = el('button', 'link-btn login-swap', 'Use a recovery code instead');
    swap.id = 'stepup-swap';
    swap.type = 'button';
    var actions = el('div', 'login-actions');
    var go = el('button', 'primary', 'Confirm');
    go.id = 'stepup-go';
    go.type = 'submit';
    var cancel = el('button', null, 'Cancel');
    cancel.id = 'stepup-cancel';
    cancel.type = 'button';
    actions.appendChild(go);
    actions.appendChild(cancel);
    [title, why, err, pwLabel, pw, codeLabel, code, recLabel, rec, swap, actions].forEach(function (x) { form.appendChild(x); });
    dlg.appendChild(form);
    document.body.appendChild(dlg);

    swap.addEventListener('click', function () {
      setRecovery(!state.recovery);
      $(state.recovery ? 'stepup-recovery' : 'stepup-code').focus();
    });
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

  function setRecovery(on) {
    state.recovery = on;
    var second = state.secondFactor;
    $('stepup-code-label').hidden = !second || on;
    $('stepup-code').hidden = !second || on;
    $('stepup-recovery-label').hidden = !second || !on;
    $('stepup-recovery').hidden = !second || !on;
    $('stepup-swap').hidden = !second;
    $('stepup-swap').textContent = on ? 'Use the code from your app instead' : 'Use a recovery code instead';
    $('stepup-code').value = '';
    $('stepup-recovery').value = '';
    setError('', []);
  }

  function setError(text, bad) {
    $('stepup-error').textContent = text;
    ['stepup-password', 'stepup-code', 'stepup-recovery'].forEach(function (id) { $(id).setAttribute('aria-invalid', bad.indexOf(id) >= 0 ? 'true' : 'false'); });
  }

  function submit(e) {
    e.preventDefault();
    if (!state || state.busy) return;
    var pw = $('stepup-password');
    var fields = { password: pw.value };
    if (!pw.value) { setError('Enter your password.', ['stepup-password']); pw.focus(); return; }
    if (state.secondFactor && !state.recovery) {
      var c = $('stepup-code').value.replace(/\s+/g, '');
      if (!/^[0-9]{6}$/.test(c)) { setError('Enter the 6 digits your app shows.', ['stepup-code']); $('stepup-code').focus(); return; }
      fields.code = c;
    } else if (state.secondFactor) {
      var r = $('stepup-recovery').value.trim();
      if (!r) { setError('Enter a recovery code.', ['stepup-recovery']); $('stepup-recovery').focus(); return; }
      fields.recovery = r;
    }
    var go = $('stepup-go');
    state.busy = true;
    go.disabled = true;
    setError('', []);
    var s = state;
    Promise.resolve(s.send(fields)).then(function (answer) {
      if (state !== s) return;
      var b = answer && answer.body ? answer.body : {};
      // A wrong password or code: said here, and the visitor tries again.
      if (answer && ((answer.status === 400 && (b.field === 'password' || b.field === 'code' || b.field === 'recovery')) || answer.status === 429)) {
        var id = b.field === 'code' ? 'stepup-code' : b.field === 'recovery' ? 'stepup-recovery' : 'stepup-password';
        if (b.secondFactor && !s.secondFactor) { s.secondFactor = true; setRecovery(false); }
        setError(b.error || 'That did not work. Try again.', [id]);
        if (b.field !== 'password') { $('stepup-code').value = ''; $('stepup-recovery').value = ''; }
        $(id === 'stepup-code' && s.recovery ? 'stepup-recovery' : id).focus();
        return;
      }
      s.answer = answer;
      dlg.close();
    }, function () {
      if (state === s) setError('Could not reach the server. Try again.', []);
    }).then(function () {
      s.busy = false;
      go.disabled = false;
    });
  }

  window.rettuiStepUp = {
    // opts: {title, why, action, secondFactor, send}. Resolves with the answer, or null.
    ask: function (opts) {
      return new Promise(function (resolve) {
        if (!dlg) build();
        if (state) { resolve(null); return; }
        state = { resolve: resolve, answer: null, busy: false, recovery: false, secondFactor: opts.secondFactor === true, send: opts.send, back: document.activeElement };
        $('stepup-title').textContent = opts.title;
        $('stepup-why').textContent = (opts.why ? opts.why + ' ' : '') + (state.secondFactor ? 'Enter your password and the code your app shows now.' : 'Enter your password.');
        $('stepup-go').textContent = opts.action || 'Confirm';
        $('stepup-go').className = opts.danger ? 'danger' : 'primary';
        setRecovery(false);
        dlg.showModal();
        $('stepup-password').focus();
      });
    }
  };
})();
