// GET /feed.xml: an Atom 1.0 feed of the latest release of each repository, built only from the
// release cache (no request to GitHub is made for a visitor). Everything that goes into it is escaped
// for XML and cleaned of characters XML does not allow, so a release note can never break the document.
import crypto from 'node:crypto';

export const FEED_TYPE = 'application/atom+xml; charset=utf-8';
export const FEED_TITLE = 'rettui releases';
export const MAX_FEED_CONTENT = 4000;
// The feed's own id when there is no site address: a tag URI, which stays the same wherever it is served.
export const FEED_ID = 'tag:rettui.dev,2026:releases';
const EPOCH = '1970-01-01T00:00:00Z';

// What XML 1.0 does not allow, or discourages: most control characters, the C1 range, the two
// non-characters, and a half of a surrogate pair.
const INVALID_XML = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F￾￿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

export const xmlText = (value) =>
  String(value ?? '')
    .replace(INVALID_XML, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');

// The notes cut to max characters (whole characters, never half of a pair), with an ellipsis when cut.
export function truncateText(value, max = MAX_FEED_CONTENT) {
  const clean = String(value ?? '').replace(INVALID_XML, '');
  const chars = [...clean];
  return chars.length <= max ? clean : `${chars.slice(0, max - 1).join('').trimEnd()}…`;
}

function isoOrNull(value) {
  const t = typeof value === 'string' || typeof value === 'number' ? new Date(value) : null;
  return t && Number.isFinite(t.getTime()) ? t.toISOString().replace(/\.\d{3}Z$/, 'Z') : null;
}

// items: [{repo, fetchedAt, release}] from ReleaseCache.feedItems. siteUrl: the origin or null.
// Returns the XML text. Newest first, then in the order given.
export function buildFeed(items, { siteUrl = null } = {}) {
  const entries = items
    .map((item) => ({ ...item, updated: isoOrNull(item.release.publishedAt) ?? isoOrNull(item.fetchedAt) ?? EPOCH }))
    .sort((a, b) => (a.updated < b.updated ? 1 : a.updated > b.updated ? -1 : 0));
  const updated = entries.length ? entries[0].updated : EPOCH;
  const out = ['<?xml version="1.0" encoding="utf-8"?>', '<feed xmlns="http://www.w3.org/2005/Atom">'];
  out.push(`  <id>${xmlText(siteUrl ? `${siteUrl}/feed.xml` : FEED_ID)}</id>`);
  out.push(`  <title>${xmlText(FEED_TITLE)}</title>`);
  out.push('  <subtitle>The latest release notes of rettui and rngit-rs</subtitle>');
  out.push(`  <updated>${updated}</updated>`);
  if (siteUrl) {
    out.push(`  <link rel="self" type="application/atom+xml" href="${xmlText(`${siteUrl}/feed.xml`)}"/>`);
    out.push(`  <link rel="alternate" type="text/html" href="${xmlText(`${siteUrl}/downloads`)}"/>`);
  }
  out.push('  <author><name>rettui</name></author>');
  for (const { repo, release, updated: when } of entries) {
    const project = repo.split('/').pop();
    const notes = truncateText(release.notes ?? '');
    out.push('  <entry>');
    out.push(`    <id>${xmlText(release.url)}</id>`);
    out.push(`    <title>${xmlText(`${project} ${release.name}`)}</title>`);
    out.push(`    <updated>${when}</updated>`);
    out.push(`    <link rel="alternate" type="text/html" href="${xmlText(release.url)}"/>`);
    out.push(`    <content type="text">${xmlText(notes || `${project} ${release.tag}. No release notes were published.`)}</content>`);
    out.push('  </entry>');
  }
  out.push('</feed>', '');
  return out.join('\n');
}

export const feedEtag = (body) => `"${crypto.createHash('sha256').update(body).digest('hex').slice(0, 24)}"`;
