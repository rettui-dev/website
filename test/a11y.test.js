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

test('the passkey list works at phone width: it wraps, and the buttons are large enough to touch', async () => {
  const css = await read('site.css');
  assert.match(css, /\.acct-passkey \{[^}]*overflow-wrap: anywhere/);
  assert.match(css, /\.acct-passkeys \{[^}]*display: grid/);
  // Buttons in the list use the same 40px touch size as the other account buttons.
  assert.match(css, /\.login-actions button \{ min-height: 40px/);
  assert.match(css, /\.acct-passkey \.acct-form \{ max-width: none; \}/);
});
