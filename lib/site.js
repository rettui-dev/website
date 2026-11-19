// Site mode and branding. In "status" mode the server is only the status page
// (plus its API); the rettui project pages answer 404. The optional site:
// section of the config file gives the status page a name, a logo, links and
// texts of the operator's own. The page is the same file as ever: for a custom
// site it is filled in here, on the server, with every value escaped, so the
// strict CSP (no inline script or style) stays as it is and the browser never
// gets markup from the config.
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';

export const SITE_MODES = ['full', 'status'];
export const MAX_LOGO_BYTES = 512 * 1024;
export const MAX_SITE_NAME = 48;
export const MAX_SITE_LINKS = 6;
export const MAX_LINK_LABEL = 32;
export const MAX_LINK_URL = 300;
export const MAX_SITE_TEXT = 200;
export const LOGO_URL = '/brand/site-logo';

// Pages and files that belong to the rettui project site; in status mode they do not exist.
export const PROJECT_FILES = ['index.html', 'join.html', 'downloads.html', 'downloads.js', 'copy.js'];

export const NO_SITE = Object.freeze({ name: null, logo: null, links: Object.freeze([]), description: null, footer: null, url: null });
export const MAX_SITE_URL = 200;

// The address the site is served at, for the links that must be absolute (the feed, og:url, og:image):
// https, a host, no user name, password, path, query or fragment. Returns the origin ("https://host"),
// or throws Error with a short reason that does not repeat the value.
export function parseSiteUrl(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_SITE_URL) throw new Error(`must be an https URL of up to ${MAX_SITE_URL} characters`);
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new Error('is not a URL');
  }
  if (u.protocol !== 'https:' || u.hostname === '') throw new Error('must be an https URL');
  if (u.username || u.password) throw new Error('must not contain a user name or password');
  if (u.pathname !== '/' || /[?#]/.test(value)) throw new Error('must be only the address of the site, like https://example.org (no path, query or fragment)');
  return u.origin;
}

// What a logo file is, from its first bytes; null when it is none of the four kinds.
// An SVG is only ever shown through an <img>, where scripts do not run, but one
// that carries script, a foreign object or an event handler is refused anyway.
export function sniffLogo(buf) {
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length >= 12 && buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') return 'image/webp';
  const text = buf.toString('utf8').replace(/^﻿/, '');
  if (/^\s*(<\?xml[^>]*\?>\s*|<!--[\s\S]*?-->\s*|<!DOCTYPE\s+svg[^>]*>\s*)*<svg[\s>]/i.test(text) && !/<script|<foreignObject|<!ENTITY|\son[a-z]+\s*=/i.test(text)) return 'image/svg+xml';
  return null;
}

// Reads a logo file: a regular file of at most MAX_LOGO_BYTES, opened first and
// checked through the handle. Throws Error with a short reason, never the path
// or the content.
export async function readLogo(file) {
  let handle;
  try {
    handle = await fs.open(file, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
    const st = await handle.stat();
    if (!st.isFile() || st.size > MAX_LOGO_BYTES) throw new Error('is not a regular file of at most 512 KiB');
    const buf = Buffer.alloc(MAX_LOGO_BYTES + 1);
    const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
    if (bytesRead > MAX_LOGO_BYTES) throw new Error('is not a regular file of at most 512 KiB');
    const bytes = Buffer.from(buf.subarray(0, bytesRead));
    const mime = sniffLogo(bytes);
    if (!mime) throw new Error('is not a PNG, JPEG, WebP or SVG image');
    return { bytes, mime };
  } catch (err) {
    if (err.code === undefined) throw err;
    throw new Error(`cannot be read (${err.code})`);
  } finally {
    await handle?.close().catch(() => {});
  }
}

export const resolveLogoPath = (configFile, value) => path.resolve(path.dirname(configFile), value);

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// True when the site section changes anything on the page.
export function hasBranding(site) {
  return Boolean(site.name || site.logo || site.links.length || site.description || site.footer);
}

// The blocks of status.html that are filled in. Each must be there exactly as
// written, so a change to the page that moves one fails loudly (and a test).
const BLOCKS = {
  title: /<title>[^<]*<\/title>/,
  description: /<meta name="description" content="[^"]*">/,
  icon: /<link rel="icon" type="image\/png" href="\/brand\/icon\.png">/,
  touchIcon: /<link rel="apple-touch-icon" href="\/brand\/icon\.png">/,
  ogSiteName: /<meta property="og:site_name" content="[^"]*">/,
  ogTitle: /<meta property="og:title" content="[^"]*">/,
  ogDescription: /<meta property="og:description" content="[^"]*">/,
  brand: /<a class="brand" href="\/">[\s\S]*?<\/a>/,
  nav: /(<nav class="links" aria-label="Site">)([\s\S]*?)(<\/nav>)/,
  banner: /<div id="banner"/,
  footer: /(<footer>\s*<div class="wrap">)([\s\S]*?)(<\/div>\s*<\/footer>)/,
};

export const OG_CARD = '/brand/og-card.png';
export const RASTER_LOGOS = ['image/png', 'image/jpeg', 'image/webp'];

// The Open Graph tags that need the site's address: og:url, and the picture when there is one. They are
// added only when the operator has set the address (site.url), because both must be absolute URLs.
// image: {path, width?, height?, alt?} or null. Every value is escaped.
export function openGraphTail({ origin, path: pagePath, image }) {
  const tags = [`<meta property="og:url" content="${esc(origin + pagePath)}">`];
  if (image) {
    tags.push(`<meta property="og:image" content="${esc(origin + image.path)}">`);
    if (image.width) tags.push(`<meta property="og:image:width" content="${image.width}">`, `<meta property="og:image:height" content="${image.height}">`);
    if (image.alt) tags.push(`<meta property="og:image:alt" content="${esc(image.alt)}">`);
  }
  tags.push(`<meta name="twitter:card" content="${image && image.width ? 'summary_large_image' : 'summary'}">`);
  if (image) tags.push(`<meta name="twitter:image" content="${esc(origin + image.path)}">`);
  return `${tags.join('\n')}\n`;
}

function addToHead(html, tags) {
  if (!html.includes('</head>')) throw new Error('the page has no head to add the tags to');
  return html.replace('</head>', () => `${tags}</head>`);
}

// A rettui project page (home, join, downloads) with its address and picture added; the page itself is
// served unchanged when there is no site address.
export function renderProjectPage(html, { origin, path: pagePath }) {
  return addToHead(html, openGraphTail({ origin, path: pagePath, image: { path: OG_CARD, width: 1200, height: 630, alt: 'rettui: a Reticulum client for the terminal, browser and Android' } }));
}

// The status page for this site. mode and site as loadNodes gives them.
export function renderStatus(html, { mode, site }) {
  const sub = (key, make) => {
    if (!BLOCKS[key].test(html)) throw new Error(`status.html: the ${key} block is missing`);
    html = html.replace(BLOCKS[key], (...m) => make(...m));
  };
  const statusMode = mode === 'status';
  const label = site.name ?? 'Status';
  const branded = statusMode || Boolean(site.name || site.logo);
  const links = site.links.map((l) => `<a href="${esc(l.url)}" rel="noopener noreferrer">${esc(l.label)}</a>`);

  if (statusMode || site.name) {
    const title = statusMode && !site.name ? 'Status' : `Status - ${esc(site.name)}`;
    sub('title', () => `<title>${title}</title>`);
    sub('ogTitle', () => `<meta property="og:title" content="${title}">`);
  }
  if (branded) sub('ogSiteName', () => `<meta property="og:site_name" content="${esc(label)}">`);
  if (site.description || statusMode) {
    const description = esc(site.description ?? 'Reachability of the Reticulum entry points');
    sub('description', () => `<meta name="description" content="${description}">`);
    sub('ogDescription', () => `<meta property="og:description" content="${description}">`);
  }
  if (site.logo) {
    sub('icon', () => `<link rel="icon" type="${site.logo.mime}" href="${LOGO_URL}">`);
    sub('touchIcon', () => (site.logo.mime === 'image/svg+xml' ? '' : `<link rel="apple-touch-icon" href="${LOGO_URL}">`));
  }
  if (statusMode || site.name || site.logo) {
    // The name beside the logo says it already, so the picture is then decoration.
    sub('brand', () => {
      const img = site.logo ? `<img class="site-logo" src="${LOGO_URL}" alt="${site.name ? '' : esc(label)}" height="28">` : '';
      const name = site.name || !site.logo ? `<span class="brand-name">${esc(label)}</span>` : '';
      return `<a class="brand" href="/">${img}${name}</a>`;
    });
  }
  sub('nav', (_all, open, inner, close) => {
    if (statusMode) return `${open}\n      <a href="/" aria-current="page">Status</a>${links.map((l) => `\n      ${l}`).join('')}\n    ${close}`;
    return `${open}${inner.replace(/\s*$/, '')}${links.map((l) => `\n      ${l}`).join('')}\n    ${close}`;
  });
  if (site.description) sub('banner', (m) => `<p class="site-description">${esc(site.description)}</p>\n  ${m}`);
  sub('footer', (_all, open, inner, close) => {
    const text = site.footer ? `\n    <span>${esc(site.footer)}</span>` : '';
    if (statusMode) return `${open}\n    <span>${esc(label)}</span>${text}\n  ${close}`;
    const named = site.name ? inner.replace('<span>rettui</span>', () => `<span>${esc(site.name)}</span>`) : inner;
    return `${open}${named.replace(/\s*$/, '')}${text}\n  ${close}`;
  });
  if (site.url) {
    // The rettui card is rettui's: a site with a name or logo of its own shows its logo (if a picture) or no image.
    let image = { path: OG_CARD, width: 1200, height: 630, alt: 'rettui: a Reticulum client for the terminal, browser and Android' };
    if (branded) image = site.logo && RASTER_LOGOS.includes(site.logo.mime) ? { path: LOGO_URL, alt: `${label} logo` } : null;
    html = addToHead(html, openGraphTail({ origin: site.url, path: statusMode ? '/' : '/status', image }));
  }
  return html;
}
