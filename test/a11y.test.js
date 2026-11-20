import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Cheap checks on the files, for what an automated audit (axe) finds in a browser: they catch a page
// that loses its language, skip link, landmark or alt text, and a theme colour that stops being readable.
const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const read = (name) => fs.readFile(path.join(publicDir, name), 'utf8');
const PAGES = ['index.html', 'status.html', 'join.html', 'downloads.html', 'account.html', 'users.html'];
// Pages that are in no menu: their nav marks no page as current.
const OFF_MENU = ['account.html', 'users.html'];

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
