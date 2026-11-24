Every page and endpoint the website serves, and how the pages look and behave: the Join and Downloads pages, the release feed, accessibility, themes and link previews.

## Pages

- `/` is the home page (the status page in status-only mode, see [Status-only site](Configuration#status-only-site)).
- `/status` shows, for each entry point, whether it is up, one line of facts (clients, peers
  heard, uptime over 24 hours, when it was last checked) and a bar of the last 90 checks. A
  line of warning appears only when something needs a look. "More" opens the rest, and "Full
  details" opens graphs. Under the bar of checks, a 90 day uptime bar shows one cell per day, and a
  "Recent incidents" list shows when nodes went down and for how long (see [Uptime history and
  incidents](Uptime-and-Alerts#uptime-history-and-incidents)). It refreshes itself and keeps open rows open. Below the banner a collapsible
  "Network map" draws each proxy as a frame around the nodes behind it, with the external peers
  they connect out to below it (see [Network map](Node-Stats#network-map)). On a phone, or when
  there are too many nodes or links to draw at once, it shows one node at a time, picked with a
  row of buttons above the map. It shows which of the nodes dial which, as arrows and as
  "Dials" and "Dialled by" chips on the nodes' cards (see [Links between nodes](Connecting-Nodes#links-between-nodes)).
- `/api/status` is the same data as JSON, with `uptime90` and `days` for each host (the incidents are in `/api/incidents`).
- `/api/incidents` lists the latest incidents (up to 100) of all nodes, newest first. Only GET
  and HEAD are allowed.
- `/api/stats?host=<host:port>&range=6h|24h|7d` is the detail of one node's stats (see
  [Stats history](Node-Stats#stats-history)). `range` defaults to `24h`. An unknown host, or one without a
  stats URL, is a 404; a bad range is a 400. Only GET and HEAD are allowed.
- `/api/logs/<host:port>?lines=<1..500>&level=<error|warn|info|debug>` is a node's recent log lines for the
  Logs tab (see [Node logs](Node-Stats#node-logs)). It needs a login (or `public_logs: true` on the node), the `details` section, and a node with a stats
  token that serves logs. Only GET and HEAD are allowed.
- `/join` explains how to connect to the entry point `rns.rettui.dev:4242` over TCP, with a
  Reticulum interface block to copy, the other entry points and a QR code for phones (see
  "Join page").
- `/join-qr.svg` is that QR code as an SVG (GET and HEAD only).
- `/downloads` lists the latest rettui and rngit-rs releases by platform, with SHA-256 checksums
  (see "Downloads page").
- `/api/releases` is the same list as JSON (GET and HEAD only, `no-store`).
- `/feed.xml` is an Atom feed of the latest release notes (see "Release feed").
- `/api/public/stats` and `/api/public/incidents` are the public, versioned JSON API for
  dashboards (see [Public stats API](Public-Data-and-Stats-API#public-stats-api)).
- `/healthz` answers `ok` (used by the Docker health check).
- `/login` and `/logout` (POST only) exist only when the config file has users (see [Logins](Logins#logins)).
- `/api/session` answers `{enabled, name}`: whether the site has users, and the name of whoever is signed in
  (`null` if nobody), and `mustChangePassword: true` while their password is one an admin set.
  The Sign in button on every page asks it. GET and HEAD only, never cached.
- `/users` and `/api/users` are the Users page and its API, for admins only (see [Managing users](Managing-Users#managing-users)).
- `/manage` and `/api/manage` are the Manage page and its API, for the `manage` and `admin` roles
  only, to change a few settings of rettui nodes, a few of their Reticulum settings (tested before
  they are kept), and restart their Reticulum (see [Managing nodes](Managing-Nodes#managing-nodes)).

## Join page

`/join` is static HTML (`public/join.html`) plus `/join-qr.svg`. The interface block is the one
for Reticulum's config file: a `[[name]]` section below `[interfaces]` with `type =
TCPClientInterface`, `enabled = yes`, `target_host` and `target_port` (Reticulum has no `name`
key; the section title is the name). The text lives in `lib/join.js`, and a test checks that the
page shows the same text the QR code holds. The QR code is made on the server by `lib/qr.js`, a
small encoder with no dependency (byte mode, level M, versions 1 to 10, all 8 masks). It was
checked by decoding generated images with OpenCV's QR detector for both levels at every version
and mask; `test/qr.test.js` checks the parts with published answers (Reed-Solomon, format and
version bits, capacities) and reads codes back. The copy buttons use `public/copy.js` and say
"Copied" in a `role="status"` element.

## Downloads page

`lib/releases.js` asks `https://api.github.com/repos/<owner>/<repo>/releases/latest` in the
background, at most every 15 minutes for each repository (a failed try is repeated after 30
seconds, doubling up to 15 minutes). Visitors only read the cache: `/api/releases` and the
page never start a request. The cache is kept in memory and in `releases.json` in `DATA_DIR`
(written atomically), so a restart shows something at once. When GitHub cannot be reached the
last good copy is shown, marked stale with its age.

- **What is trusted:** nothing. The answer is limited to 1 MiB and 10 seconds, redirects are
  followed only to GitHub's own hosts, every field is checked and cut to a length, and a download
  link is kept only if it is `https://github.com/<owner>/<repo>/releases/download/<tag>/<file>`
  of the same repository. The release page link is built here, not taken from the answer. The
  token is sent to `api.github.com` only and is never logged or shown; failures are logged as a
  repository and a short code (for example `http 403`, `rate limited`, `timeout`).
- **Checksums:** the `digest` GitHub gives for each file (`sha256:...`). If a file has none, the
  release's checksum files (`SHA256SUMS`, `*checksums*`, `*.sha256`; at most 3, same limits) are
  read. Otherwise the page says "no checksum published".
- **Platforms** are worked out from file names (`lib/releases.js`, `classifyAsset`): Linux x86_64
  and aarch64, macOS (Apple silicon, Intel), Windows, Android, Docker, source, checksums, other.
- **Layout:** one card for each platform, with its main file first (the plain rettui build, before
  the desktop app and the packages), its SHA-256 and a Copy button; the other files of that
  platform are in a folded "N more files for <platform>" list, which opens with the keyboard.
  Every checksum is plain text on the page, so it can also be read or selected by hand.
- **No release yet** (or a repository GitHub does not know) shows a plain message and a link to
  its releases page.

## Release feed

`GET /feed.xml` (GET and HEAD only, anything else is 405) is an Atom 1.0 feed
(`application/atom+xml; charset=utf-8`) with the latest release of each repository in
`RELEASE_REPOS`, newest first. It is built from the same cache as the Downloads page, so a request
never starts one to GitHub, and an empty cache gives an empty but valid feed. Each entry has the
release page as its `id` and as its `rel="alternate"` link, `updated` from the publish date (a release without a usable date gets 1970-01-01, so the entry does not look new at every refresh), a
title such as `rettui rettui v2.1.0`, and the release notes as `type="text"` content, cut to 4000
characters. Everything is escaped, and characters XML does not allow are dropped. The notes are
kept in `releases.json` (cleaned and capped at 4000 characters; an older file without them fills
in at the next refresh) but are not part of `/api/releases`. The answer has an `ETag` and
`Cache-Control: public, max-age=300`.

With `SITE_URL` (or `site.url` in the config file) the feed also names itself (`id` and `rel="self"`
use `https://<site>/feed.xml`) and links to the Downloads page. Without it the feed id is
`tag:rettui.dev,2026:releases`, and only the GitHub links are in it, as a relative link would mean
nothing in a reader. The home and Downloads pages advertise it with
`<link rel="alternate" type="application/atom+xml">`. In status-only mode `/feed.xml` is 404.

## Accessibility and themes

Checked with axe-core (WCAG 2.2 AA and best practice) on the four pages, the status-only variant,
the opened rows, the network map and the Details dialog, in both themes at 1200 and 375 pixels, with
no violations. What the pages do: a "Skip to content" link first on every page, `lang="en"`, header,
nav, main and footer landmarks, one `h1`, `aria-current="page"` in the menu, a focus ring on every
control (the network map's nodes, frames and buttons too), text at least 4.5:1 and control borders at least 3:1 in both
themes, touch targets of 24 pixels or more (40 on phones), no sideways scrolling at 320 pixels or at
200% zoom, and no animation when the system asks for less motion. With no saved choice the theme
follows the system (`prefers-color-scheme`), also when it changes while the page is open; the theme
button saves a choice. `test/a11y.test.js` checks the files for these and the theme colours for
contrast; it is not a replacement for running axe in a browser. The Account, Users and Manage pages
are built the same way and are in those file checks too; run axe on `/manage` (signed in as a
`manage` user, with a node set up, and once with a Reticulum change on probation) before a release
that changes it.

**Width.** The header and footer are 1400 pixels wide on every page, so the logo and the menu stay
in the same place when you go from one page to another. The page text is as wide as the page needs:
Home stays 900 pixels, and Status, Manage, Join, Downloads, Account and Users use up to 1400. Every
layout below is only on from the width given, so on a phone, or at 400% zoom, each page is one column.

- **Status.** From 1100 pixels the entry points are on the left, in two columns when there is room,
  and the recent incidents stay in view beside them.
- **Manage.** From 1100 pixels a list of links to the sections is on the left; the fields, the read
  only Reticulum tables and the change form flow into columns, and the Save bar stays at the bottom
  of the screen.
- **Users.** The table has the whole width from 1100 pixels. Below that each user is a card, so the
  eight columns never get cramped. "Add a user" is a card of its own under the table.
- **Account.** From 1000 pixels the cards are in two columns, in reading order (Profile and Password,
  then App code and Passkeys, and so on). The "your password was set by an admin" notice spans both.
- **Downloads.** From 1000 pixels rettui and rngit-rs are side by side. The text keeps its line length.
- **Join.** From 1100 pixels the QR code and the other entry points are in a column on the right.
  It stays in view while you scroll, but only when the window is at least 700 pixels tall, so on a
  short window nothing is out of reach.
- Reading order and tab order are the page order everywhere: left column, then right, row by row.

## Link previews (Open Graph)

Every page (home, status, Join, Downloads) has `description`, `theme-color` (dark and light),
`og:title`, `og:description`, `og:type` and `og:site_name` in the file itself. The tags that must be
absolute URLs are added by the server, and only when it knows its own address (`SITE_URL`, or
`site.url` in the config file): `og:url`, `og:image` (`/brand/og-card.png`, 1200 by 630, with its
size and a text for it), `twitter:card=summary_large_image` and `twitter:image`. Without the address
those tags are left out rather than guessed, and the pages are served byte for byte as the files.
The card is a static file, drawn once from the site's own logo, colours and font, and is under
150 KB.

On the status page the tags follow the branding: the name and description from the `site:` section
(or "Status" and the usual description in status-only mode), escaped like the rest of the page. A
page with a name or logo of its own does not use the rettui card: `og:image` is then the site's logo
(`/brand/site-logo`) when it is a PNG, JPEG or WebP picture (card type `summary`), and left out
for an SVG or no logo. In status-only mode the project pages and their tags do not exist.
