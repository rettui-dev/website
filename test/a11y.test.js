import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Cheap checks on the files, for what an automated audit (axe) finds in a browser: they catch a page
// that loses its language, skip link, landmark or alt text, and a theme colour that stops being readable.
const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const read = (name) => fs.readFile(path.join(publicDir, name), 'utf8');
const PAGES = ['index.html', 'status.html', 'join.html', 'downloads.html', 'account.html', 'users.html', 'manage.html'];
// Pages that are in no menu: their nav marks no page as current.
const OFF_MENU = ['account.html', 'users.html', 'manage.html'];

test('every page has a language, a viewport that allows zoom, and a title', async () => {
  for (const name of PAGES) {
    const html = await read(name);
    assert.match(html, /<html lang="en"[ >]/, name);
    const viewport = /<meta name="viewport" content="([^"]*)"/.exec(html)?.[1] ?? '';
    assert.match(viewport, /width=device-width/, name);
    assert.doesNotMatch(viewport, /user-scalable\s*=\s*(no|0)|maximum-scale/i, `${name}: zoom is blocked`);
    assert.match(html, /<title>[^<]+<\/title>/, name);
    assert.match(html, /<meta name="color-scheme" content="dark light">/, name);
  }
});

test('every page starts with a skip link to a main landmark, and has one h1 and the landmarks', async () => {
  for (const name of PAGES) {
    const html = await read(name);
    const firstLink = /<body>\s*<a class="skip-link" href="#main">Skip to content<\/a>/.exec(html);
    assert.ok(firstLink, `${name}: the skip link is the first thing in the body`);
    assert.equal((html.match(/<main\b/g) ?? []).length, 1, name);
    assert.match(html, /<main id="main" tabindex="-1"/, name);
    assert.equal((html.match(/<h1\b/g) ?? []).length, 1, `${name}: one h1`);
    assert.match(html, /<header class="top">/, name);
    assert.match(html, /<nav class="links" aria-label="Site">/, name);
    assert.match(html, /<footer>/, name);
  }
});

test('ids are unique, images have alt text, and no tabindex is positive', async () => {
  for (const name of PAGES) {
    const html = await read(name);
    const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]);
    assert.equal(new Set(ids).size, ids.length, `${name}: duplicate id in ${ids.join(',')}`);
    for (const [tag] of html.matchAll(/<img\b[^>]*>/g)) assert.match(tag, /\salt="/, `${name}: ${tag}`);
    for (const [, n] of html.matchAll(/tabindex="(-?\d+)"/g)) assert.ok(Number(n) <= 0, `${name}: tabindex ${n}`);
    // Every in-page link points at something.
    for (const [, target] of html.matchAll(/href="#([^"]+)"/g)) assert.ok(ids.includes(target), `${name}: #${target}`);
  }
});

test('the nav marks exactly one page as current, and buttons and inputs have names', async () => {
  for (const name of PAGES) {
    const html = await read(name);
    const nav = /<nav class="links"[^>]*>([\s\S]*?)<\/nav>/.exec(html)[1];
    assert.equal((nav.match(/aria-current="page"/g) ?? []).length, OFF_MENU.includes(name) ? 0 : 1, name);
    // Every button has its words in the file (the sign in buttons too: account.js only changes them).
    for (const [, inner] of html.matchAll(/<button\b[^>]*>([\s\S]*?)<\/button>/g)) {
      assert.ok(inner.replace(/<[^>]*>/g, '').trim().length > 0, `${name}: empty button`);
    }
    for (const [tag] of html.matchAll(/<input\b[^>]*>/g)) {
      const id = /\sid="([^"]+)"/.exec(tag)?.[1];
      assert.ok(/aria-label=/.test(tag) || (id && new RegExp(`<label[^>]*for="${id}"`).test(html)), `${name}: ${tag} has no label`);
    }
  }
});

// WCAG contrast of two #rrggbb colours.
function ratio(a, b) {
  const lum = (hex) => {
    const n = parseInt(hex.slice(1), 16);
    const lin = (c) => ((c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return 0.2126 * lin(n >> 16) + 0.7152 * lin((n >> 8) & 255) + 0.0722 * lin(n & 255);
  };
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

test('theme colours: text is at least 4.5:1 and control borders 3:1, in both themes', async () => {
  const css = await read('site.css');
  const vars = (block) => Object.fromEntries([...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6});/gi)].map((m) => [m[1], m[2]]));
  const dark = vars(/:root \{([\s\S]*?)\n\}/.exec(css)[1]);
  const light = { ...dark, ...vars(/:root\[data-theme=light\] \{([\s\S]*?)\n\}/.exec(css)[1]) };
  for (const [theme, t] of [['dark', dark], ['light', light]]) {
    for (const fg of ['text', 'dim', 'accent', 'green', 'yellow', 'red']) {
      for (const bg of ['bg', 'panel', 'raised', 'sunken']) assert.ok(ratio(t[fg], t[bg]) >= 4.5, `${theme}: ${fg} on ${bg} is ${ratio(t[fg], t[bg]).toFixed(2)}`);
    }
    assert.ok(ratio(t['on-accent'], t.accent) >= 4.5, `${theme}: text on the accent`);
    for (const bg of ['bg', 'panel', 'raised', 'sunken']) assert.ok(ratio(t.control, bg === 'bg' ? t.bg : t[bg]) >= 3, `${theme}: control border on ${bg}`);
  }
});

test('the style sheet has a visible focus style, a skip link, and respects reduced motion', async () => {
  const css = await read('site.css');
  assert.match(css, /:focus-visible \{ outline: 2px solid var\(--accent\)/);
  assert.match(css, /\.skip-link:focus/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
  const theme = await read('theme.js');
  assert.match(theme, /prefers-color-scheme: light/);
});

test('the passkey section is a labelled region with named controls, messages that are read out, and hints for password managers', async () => {
  const html = await read('account.html');
  for (const id of ['acct-passkeys', 'acct-recovery']) {
    const section = new RegExp(`<section id="${id}"[^>]*aria-labelledby="([^"]+)"[^>]*hidden>`).exec(html);
    assert.ok(section, `${id} is a hidden section with a name`);
    assert.match(html, new RegExp(`<h2 id="${section[1]}"`), id);
  }
  // The name field has a visible label, and a text field never gets filled in by a password manager.
  assert.match(html, /<label for="passkey-name">[^<]+<\/label>\s*<input id="passkey-name" type="text"[^>]*maxlength="64"/);
  for (const [tag] of html.matchAll(/<input\b[^>]*type="text"[^>]*>/g)) {
    if (/\sreadonly\b/.test(tag)) continue; // the hidden name for the password manager, on purpose
    for (const a of ['data-bwignore="true"', 'data-1p-ignore="true"', 'data-lpignore="true"']) assert.ok(tag.includes(a), `${a} on ${tag}`);
  }
  // Errors are read out as they appear; the page's status line is a polite status.
  for (const id of ['passkey-add-error', 'codes-new-error', 'totp-disable-error']) assert.match(html, new RegExp(`<p id="${id}" class="login-error" role="alert">`), id);
  assert.match(html, /<p id="acct-status" class="note" role="status">/);
  // The unavailable reason is text on the page, not only a disabled button.
  assert.match(html, /<p id="passkeys-unavailable" class="note" hidden><\/p>/);
  assert.match(html, /<h2 id="acct-passkeys-h" tabindex="-1">/);
});

test('the sign in and step-up dialogs: the passkey button is a button with words, the errors are read out, and the code fields keep the hints', async () => {
  const sign = await read('account.js');
  assert.match(sign, /el\('button', 'primary', 'Use your passkey'\)/);
  assert.match(sign, /err\.id = 'login-code-error';\s*err\.setAttribute\('role', 'alert'\)/);
  assert.match(sign, /rec\.setAttribute\(a, 'true'\)/);
  const step = await read('step-up.js');
  assert.match(step, /Use your passkey instead/);
  assert.match(step, /err\.setAttribute\('aria-live', 'assertive'\)/);
  assert.match(step, /\['data-bwignore', 'data-1p-ignore', 'data-lpignore'\]\.forEach/);
  // Passkey prompts are never started by a script on its own: the only calls are in click and submit handlers.
  assert.doesNotMatch(await read('passkey.js'), /addEventListener|setTimeout|DOMContentLoaded/);
});

test('the "Sign in with a passkey" button: a real button with words, hidden unless offered, read-out errors, touch size, and no inline script or style', async () => {
  const sign = await read('account.js');
  // The accessible name is its visible words; it is a button of type button, so Enter in the password field still sends the password.
  assert.match(sign, /var alone = el\('button', 'login-passkey-only', 'Sign in with a passkey'\);/);
  assert.match(sign, /alone\.id = 'login-passkey-only';\s*alone\.type = 'button';/);
  assert.doesNotMatch(sign, /login-passkey-only[^\n]*aria-label/);
  // "or" is plain text between the two ways; the button is hidden unless the server, the address and the browser allow it.
  assert.match(sign, /el\('p', 'login-or', 'or'\)/);
  assert.match(sign, /or\.hidden = alone\.hidden = !passkeyAlone;/);
  assert.match(sign, /s\.passkeySignIn === true && typeof s\.passkeyOrigin === 'string' && location\.origin === s\.passkeyOrigin/);
  assert.match(sign, /window\.rettuiPasskey\.supported\(\) === true/);
  // Its words go to the alert line of the dialog, which is read out, and mark no field.
  assert.match(sign, /err\.id = 'login-error';\s*err\.setAttribute\('role', 'alert'\)/);
  assert.match(sign, /function setPasskeyError\(text\) \{[^}]*'aria-invalid', 'false'[^}]*'aria-invalid', 'false'/);
  // Touch size, and a visible keyboard focus from the shared style sheet.
  const css = await read('site.css');
  assert.match(css, /\.login-passkey-only \{[^}]*min-height: 40px/);
  assert.match(css, /\.login-or \{/);
  // The script builds the dialog from nodes: no markup in strings, and no inline script or style anywhere in it.
  assert.doesNotMatch(sign, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|\.style\b|setAttribute\('style'|cssText/);
  for (const name of PAGES) {
    const html = await read(name);
    assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)[^>]*>/, `${name}: inline script`);
    assert.doesNotMatch(html, /\sstyle="|<style\b|\sonclick=|\sonload=/, `${name}: inline style or handler`);
  }
  // The account page's passkeys note is a paragraph the script can swap, in the file's own words first.
  assert.match(await read('account.html'), /<p id="passkeys-note" class="note">[^<]+<\/p>/);
});

test('the passkey list works at phone width: it wraps, and the buttons are large enough to touch', async () => {
  const css = await read('site.css');
  assert.match(css, /\.acct-passkey \{[^}]*overflow-wrap: anywhere/);
  assert.match(css, /\.acct-passkeys \{[^}]*display: grid/);
  // Buttons in the list use the same 40px touch size as the other account buttons.
  assert.match(css, /\.login-actions button \{ min-height: 40px/);
  assert.match(css, /\.acct-passkey \.acct-form \{ max-width: none; \}/);
});

test('the Reticulum panel of the manage page is a labelled region with a heading, a status that is read out and no controls', async () => {
  const html = await read('manage.html');
  const panel = /<section id="manage-ret"([^>]*)>([\s\S]*?)<\/section>/.exec(html);
  assert.ok(panel, 'the panel is there');
  assert.match(panel[1], /aria-labelledby="manage-ret-h"/);
  assert.match(panel[2], /<h2 id="manage-ret-h">Reticulum configuration<\/h2>/);
  assert.match(panel[2], /<p id="manage-ret-status"[^>]*role="status"/);
  assert.doesNotMatch(panel[2], /<(input|button|select|textarea|form)\b/, 'read only');
  // The tables the page builds have a caption, column headers and row headers.
  const js = await read('manage-page.js');
  assert.match(js, /el\('caption', 'sr-only'/);
  assert.match(js, /th\.scope = 'col'/);
  assert.match(js, /th\.scope = 'row'/);
  assert.match(js, /el\('h3'/);
});

test('the Reticulum change panel: a labelled region, its states read out, its errors announced, and a danger button that says what happens', async () => {
  const html = await read('manage.html');
  const panel = /<section id="manage-ret-edit"([^>]*)>([\s\S]*?)<\/section>/.exec(html);
  assert.ok(panel, 'the panel is there');
  assert.match(panel[1], /aria-labelledby="manage-ret-edit-h"/);
  assert.match(panel[1], /\shidden$/);
  assert.match(panel[2], /<h2 id="manage-ret-edit-h" tabindex="-1">Change the Reticulum configuration<\/h2>/);
  // Restarting, on probation, rolling back, kept, rolled back: one status that is read out politely;
  // a refusal is an alert. Both stay outside the form, so they are heard while the form is hidden.
  assert.match(panel[2], /<div id="manage-ret-live" role="status">\s*<p id="manage-ret-pending" class="note"><\/p>\s*<ul id="manage-ret-checks" class="manage-changes" aria-label="The node's checks of the change" hidden><\/ul>\s*<\/div>/);
  assert.match(panel[2], /<p id="manage-ret-error" class="login-error" role="alert"><\/p>/);
  const form = /<form id="manage-ret-form"[^>]*>([\s\S]*?)<\/form>/.exec(panel[2]);
  assert.ok(form);
  assert.doesNotMatch(form[1], /role="(status|alert)"/);
  // The button is a danger button with words, described by the text of what happens.
  assert.match(form[1], /<button id="manage-ret-apply" type="submit" class="danger" aria-describedby="manage-ret-apply-help">Apply and test<\/button>/);
  assert.match(form[1], /<p id="manage-ret-apply-help" class="note">Reticulum restarts\. The website then checks that it can still reach this node and keeps the change\. If it can't within 5 minutes, the node puts the old config back by itself\.<\/p>/);
  assert.doesNotMatch(panel[0], /\sstyle=|<script/);
  // The controls the page builds have a label each, a help text and the error in their description,
  // and are grouped in a fieldset with a legend per section.
  const js = await read('manage-page.js');
  assert.match(js, /label\.htmlFor = id;/);
  assert.match(js, /input\.setAttribute\('aria-describedby', helpId \+ ' manage-ret-error'\)/);
  assert.match(js, /fs\.appendChild\(el\('legend', null, path\.join\(' \/ '\)\)\)/);
  assert.match(js, /\$\('manage-ret-pending'\)\.textContent = /);
  // The checks are list items with text, inside the same status region.
  assert.match(js, /list\.appendChild\(el\('li', null, String\(c\.interface\) \+ ': ' \+ words\)\)/);
});

test('the passkey boxes of the password change and the password reset are labelled checkboxes, ticked by default, with help that is read with them and no inline style', async () => {
  for (const [name, box, row] of [['account.html', 'pw-remove', 'pw-remove-box'], ['users.html', 'act-pk', 'act-pk-row']]) {
    const html = await read(name);
    const input = new RegExp(`<input id="${box}" type="checkbox"([^>]*)>`).exec(html)?.[1] ?? '';
    assert.match(input, /\schecked(\s|$)/, `${name}: ticked by default`);
    assert.match(input, new RegExp(`aria-describedby="${box}-help"`), name);
    assert.match(html, new RegExp(`<label for="${box}">[^<]+</label>`), name);
    assert.match(html, new RegExp(`<p id="${box}-help" class="note">`), name);
    // Laid out by the style sheet's .acct-check (a 24px box), never by a style attribute.
    assert.match(html, new RegExp(`<div id="${row}" class="acct-check" hidden>`), name);
    assert.doesNotMatch(html, /\sstyle=/, name);
  }
});

test('the status page password button: a real button with its words, hidden until the page needs it, in the line that is read as text, no inline script or style', async () => {
  const html = await read('status.html');
  assert.match(html, /<div id="account" class="account" hidden>\s*<p id="account-text" class="account-text"><\/p>\s*<button id="account-btn" type="button" class="link-btn">Sign in<\/button>\s*<button id="account-password-btn" type="button" class="link-btn" hidden>Enter your password to see everything<\/button>/);
  assert.doesNotMatch(html, /\sstyle=|\sonclick=/);
  const js = await read('status.js');
  // It is only shown by setAccount, and the dialog opens only from a click on it (or the details' own button).
  assert.match(js, /pw\.hidden = !needPassword;/);
  assert.match(js, /getElementById\('account-password-btn'\)\.addEventListener\('click'/);
  // The button in the details is a real button with its words.
  assert.match(js, /el\('button', null, 'Enter your password to see everything'\);\s+ask\.type = 'button';/);
});

test('the LXMF alerts card is a named region that is hidden until the server says it is there, with labelled fields, help that is read with them, errors that are read out and no inline style or script', async () => {
  const html = await read('account.html');
  const card = /<section id="acct-lxmf"[^>]*aria-labelledby="([^"]+)"[^>]*hidden>([\s\S]*?)<\/section>/.exec(html);
  assert.ok(card, 'a hidden section with a name');
  assert.match(html, new RegExp(`<h2 id="${card[1]}" tabindex="-1">LXMF alerts</h2>`));
  const inner = card[2];
  // The state is a status line; the page moves the focus to the heading after a change.
  assert.match(inner, /<p id="lxmf-state" role="status"><\/p>/);
  // Every field has a visible label of its own, and its help and error are read with it.
  assert.match(inner, /<label for="lxmf-address">[^<]+<\/label>\s*<input id="lxmf-address" type="text"[^>]*aria-describedby="lxmf-address-help lxmf-set-error"/);
  assert.match(inner, /<label for="lxmf-code-for">[^<]+<\/label>\s*<select id="lxmf-code-for"/);
  assert.match(inner, /<label for="lxmf-code">[^<]+<\/label>\s*<input id="lxmf-code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="\[0-9\]\{6\}" maxlength="6"[^>]*aria-describedby="lxmf-code-help lxmf-confirm-error"/);
  assert.match(inner, /<input id="lxmf-nodes" type="checkbox" aria-describedby="lxmf-nodes-help lxmf-nodes-error">\s*<label for="lxmf-nodes">Node down and recovered alerts<\/label>/);
  for (const id of ['lxmf-set-error', 'lxmf-confirm-error', 'lxmf-nodes-error']) assert.match(inner, new RegExp(`<p id="${id}" class="login-error" role="alert"></p>`), id);
  for (const id of ['lxmf-address-help', 'lxmf-code-help', 'lxmf-nodes-help']) assert.match(inner, new RegExp(`<p id="${id}" class="note">`), id);
  // The list of addresses is named by its heading; each address gets a Remove button of its own from the script, named for it.
  assert.match(inner, /<h3 id="lxmf-list-h">Your addresses<\/h3>\s*<ul id="lxmf-list" class="acct-passkeys" aria-labelledby="lxmf-list-h"><\/ul>/);
  // Password managers leave the LXMF address and code fields alone (they are not credentials): no autofill, and the three
  // marks the managers read; the code field is a one-time code, numeric. Real passwords keep their own autocomplete.
  const ignore = ['data-bwignore="true"', 'data-1p-ignore="true"', 'data-lpignore="true"'];
  for (const [tag] of inner.matchAll(/<(?:input|select)\b[^>]*(?:type="text"|<select)[^>]*>|<select\b[^>]*>/g)) for (const a of ignore) assert.ok(tag.includes(a), `${a} on ${tag}`);
  assert.match(inner, /<input id="lxmf-address" type="text" inputmode="text" autocomplete="off"/);
  assert.match(inner, /<select id="lxmf-code-for" autocomplete="off"/);
  assert.match(inner, /<input id="lxmf-code" type="text" inputmode="numeric" autocomplete="one-time-code"/);
  assert.match(html, /<input id="pw-next" type="password" autocomplete="new-password"/);
  assert.match(html, /<input id="pw-again" type="password" autocomplete="new-password"/);
  assert.doesNotMatch(html, /type="password"(?![^>]*autocomplete="(?:new|current)-password")/);
  for (const [, b] of inner.matchAll(/<button\b[^>]*>([^<]*)<\/button>/g)) assert.ok(b.trim().length > 0);
  assert.match(inner, /<div class="acct-check">\s*<input id="lxmf-nodes"/);
  // The words the card says about what is sent: what and when, never an id, a secret or an address.
  assert.match(inner, /never holds a passkey id, a secret or an IP address/);
  assert.doesNotMatch(inner, /\sstyle=|\sonclick=|\sonchange=/);
  const js = await read('account-page.js');
  // The script only sets text, and the node alerts box says what happened (the status line is polite).
  assert.doesNotMatch(js, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
  assert.match(js, /setText\(\$\('lxmf-state'\), state\);/);
  assert.match(js, /\$\('acct-lxmf-h'\)\.focus\(\);/);
});

test('the LXMF alerts card is laid out in groups with the same space between them as the other account cards: each group has its own heading, and no button sits on the next control', async () => {
  const html = await read('account.html');
  const css = await read('site.css');
  const inner = /<section id="acct-lxmf"[^>]*>([\s\S]*?)<\/section>/.exec(html)[1];
  // The groups, in reading order, each started by an h3 (the space above a group is the h3's margin, as in the passkeys card).
  const groups = [...inner.matchAll(/<h3\b[^>]*>([^<]+)<\/h3>/g)].map((m) => m[1]);
  assert.deepEqual(groups, ['Your addresses', 'Add an address', 'Confirm an address', 'Node alerts']);
  // Every form of the card starts with its heading, so the checkbox cannot sit right under the button above it.
  for (const [, tag, body] of inner.matchAll(/<form\b([^>]*)>\s*([\s\S]*?)<\/form>/g)) {
    assert.match(tag, /class="acct-form"/);
    assert.match(body, /^<h3\b/, tag);
  }
  assert.match(css, /\.acct-card h3 \{ margin: 16px 0 6px;/);
  assert.match(css, /\.login-actions \{[^}]*margin-top: 10px;/);
  assert.match(css, /\.acct-form \{ display: grid; gap: 6px;/);
  // The select is drawn like the text fields.
  assert.match(css, /\.acct-form input, \.acct-form select \{/);
  assert.doesNotMatch(inner, /\sstyle=/);
});

test('the account page does not rewrite itself when it is loaded again: no timers, no observers, no markup, and what is painted is only written when it changed', async () => {
  const js = await read('account-page.js');
  assert.doesNotMatch(js, /setInterval|MutationObserver|requestAnimationFrame|innerHTML|replaceChildren|replaceWith|\.outerHTML/);
  // paint() sets every state through the helpers that write only a difference, and leaves the cards that decide for themselves alone.
  assert.match(js, /function setText\(e, text\) \{ if \(e\.textContent !== text\) e\.textContent = text; \}/);
  assert.match(js, /function setHidden\(e, hidden\) \{ if \(e\.hidden !== hidden\) e\.hidden = hidden; \}/);
  assert.match(js, /if \(!OWN_VISIBILITY\[x\.id\]\) setHidden\(x, must\)/);
  assert.doesNotMatch(js, /x\.hidden = data\.mustChangePassword/, 'a card is not shown and hidden again in one pass');
  // A list is built again only when the data it shows changed.
  for (const key of ['sessions', 'passkeys', 'devices', 'lxmf-list', 'lxmf-waiting']) assert.match(js, new RegExp(`changed\\('${key}'`), key);
});
