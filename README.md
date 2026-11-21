# rettui website

The website for [rettui](https://github.com/rettui-dev/rettui): a home page and a
status page that checks the project's Reticulum entry points. It has the same look
as rettui's web UI (colours, Fira Sans and Fira Code, dark and light themes).

It is plain HTML, CSS and JavaScript, served by a small Node.js server
(`server.js`) with no build step and two dependencies (`yaml`, and `@simplewebauthn/server` for
passkeys, see "Passkeys"). The server also probes the hosts, keeps their history and can fetch
their node stats.

## Pages

- `/` is the home page (the status page in status-only mode, see "Status-only site").
- `/status` shows, for each entry point, whether it is up, one line of facts (clients, peers
  heard, uptime over 24 hours, when it was last checked) and a bar of the last 90 checks. A
  line of warning appears only when something needs a look. "More" opens the rest, and "Full
  details" opens graphs. Under the bar of checks, a 90 day uptime bar shows one cell per day, and a
  "Recent incidents" list shows when nodes went down and for how long (see "Uptime history and
  incidents"). It refreshes itself and keeps open rows open. Below the banner a collapsible
  "Network map" draws the proxy, the nodes behind it and the external peers they connect out to
  (see "Network map").
- `/api/status` is the same data as JSON, with `uptime90` and `days` for each host (the incidents are in `/api/incidents`).
- `/api/incidents` lists the latest incidents (up to 100) of all nodes, newest first. Only GET
  and HEAD are allowed.
- `/api/stats?host=<host:port>&range=6h|24h|7d` is the detail of one node's stats (see
  "Stats history" below). `range` defaults to `24h`. An unknown host, or one without a
  stats URL, is a 404; a bad range is a 400. Only GET and HEAD are allowed.
- `/api/logs/<host:port>?lines=<1..500>&level=<error|warn|info|debug>` is a node's recent log lines for the
  Logs tab (see "Node logs" below). It needs a login (or `public_logs: true` on the node), the `details` section, and a node with a stats
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
  dashboards (see "Public stats API").
- `/healthz` answers `ok` (used by the Docker health check).
- `/login` and `/logout` (POST only) exist only when the config file has users (see "Logins").
- `/api/session` answers `{enabled, name}`: whether the site has users, and the name of whoever is signed in
  (`null` if nobody), and `mustChangePassword: true` while their password is one an admin set.
  The Sign in button on every page asks it. GET and HEAD only, never cached.
- `/users` and `/api/users` are the Users page and its API, for admins only (see "Managing users").
- `/manage` and `/api/manage` are the Manage page and its API, for the `manage` and `admin` roles
  only, to change a few settings of rettui nodes, a few of their Reticulum settings (tested before
  they are kept), and restart their Reticulum (see "Managing nodes").

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
control (the network map's nodes too), text at least 4.5:1 and control borders at least 3:1 in both
themes, touch targets of 24 pixels or more (40 on phones), no sideways scrolling at 320 pixels or at
200% zoom, and no animation when the system asks for less motion. With no saved choice the theme
follows the system (`prefers-color-scheme`), also when it changes while the page is open; the theme
button saves a choice. `test/a11y.test.js` checks the files for these and the theme colours for
contrast; it is not a replacement for running axe in a browser. The Account, Users and Manage pages
are built the same way and are in those file checks too; run axe on `/manage` (signed in as a
`manage` user, with a node set up, and once with a Reticulum change on probation) before a release
that changes it.

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

## Run locally

Needs Node.js 24.7 or later (the login uses its built-in Argon2id, and the user store its
built-in SQLite, `node:sqlite`).

    npm start        # http://localhost:8080
    npm test
    npm run hash-password -- --name alice   # a password_hash for the config file (see "Logins")
    npm run users -- list                   # the users in the user store (see "Managing users")
    npm run users -- gen-key                # a user store key (see "The user store key")

## Docker

    docker compose up -d --build

This serves the site on port 8080. History and the user store are kept in the `status-data`
volume, so they survive restarts. The container runs as an unprivileged user (`node`, uid 1000)
with a read-only root file system; only `/data` and the `/tmp` in memory are writable. Keep
`/data` on a named local volume: the user store is a SQLite database, which must not be on NFS,
SMB or a volume shared between hosts (see "The user store"). With users, the server also needs
the user store key, as a Docker secret (see "The user store key").

Without compose:

    docker build -t rettui-website .
    docker run -d -p 8080:8080 -v status-data:/data --read-only --tmpfs /tmp rettui-website

## Settings

All optional, set in the environment (or `environment:` in `compose.yaml`).

| Variable         | Default                           | Meaning                                                  |
| ---------------- | --------------------------------- | -------------------------------------------------------- |
| `PORT`           | `8080`                            | Port to listen on.                                       |
| `HOST`           | `0.0.0.0`                         | Address to listen on.                                    |
| `DATA_DIR`       | `./data` (`/data` in Docker)      | Where `history.json`, `stats-history.json`, `uptime.json` and `releases.json` are kept, and the user store `users.db`, `audit.log` and `failures.log` (see "Accounts and second factor" and "The user store"). |
| `USERS_KEY_FILE` | none                              | The file with the user store key (see "The user store key"). Needed as soon as there are users, in the config file or in the user store; without it the server does not start then. Keep it outside `DATA_DIR`. |
| `USERS_KEY`      | none                              | The user store key itself, instead of `USERS_KEY_FILE` (not both). A file is safer: the environment of a process is easier to read and ends up in more places. |
| `STATUS_TARGETS` | the four hosts in `lib/monitor.js` | Comma separated `host:port` list to monitor.             |
| `CONFIG_FILE`    | none                              | Path of a YAML config file that lists the nodes instead of `STATUS_TARGETS` and `STATS_URLS` (see "Config file"). Users who can log in can only be set there (see "Logins"). |
| `STATS_TOKEN`    | none                              | Token sent to every stats URL to get peer lists (see "Exact peer counts"). `STATS_TOKEN_FILE` reads it from a file; `STATS_TOKEN_FILES` (`host:port=path,...`) gives one file per node. |
| `PUBLIC_DETAILS` | `true`                            | `false` removes the Details view (and `/api/stats`) for every node (see "What is public"). |
| `PUBLIC_DISK_FIGURES` | `false`                      | `true` publishes exact free and total disk space (see "What is public"). |
| `RELEASE_REPOS`  | `rettui-dev/rettui,rettui-dev/rngit-rs` | Comma separated `owner/name` list of the repositories the Downloads page shows (at most 8). Anything else is an error at start. |
| `GITHUB_TOKEN`   | none                              | Optional GitHub token that raises the API rate limit; it only reads public releases. `GITHUB_TOKEN_FILE` reads it from a file (not both): a regular file of at most 1024 bytes; a pipe, a device or a bigger file stops the server at start. |
| `SITE_MODE`      | `full`                            | `status` serves only the status page and its APIs (see "Status-only site"). Not with `CONFIG_FILE`: use `site_mode` in the file. |
| `SITE_URL`       | none                              | The https address the site is served at, like `https://rettui.example` (no path). Needed for the absolute links in the feed and in the Open Graph tags; without it they are left out. It is also the address passkeys are made for: without it there are no passkeys (see "Passkeys"), and `http://localhost` is accepted for testing. Changing it later stops existing passkeys working. Not with `CONFIG_FILE`: use `site.url` in the file. |
| `STATS_URLS`     | none                              | Comma separated `host:port=url` pairs: where to fetch each monitored host's node stats (see below). |
| `LOGIN_TRUSTED_PROXIES` | none                       | Comma separated IP addresses or networks in CIDR notation (like `172.22.0.0/16`) of the reverse proxies in front of the site (at most 16), for users in the user store without a config file: the same as `login.trusted_proxies` (see "Behind a reverse proxy"). Not with `CONFIG_FILE`: use `login.trusted_proxies` in the file. Set without users in the user store, it is not used and the server says so at start. |

A bad value (for example a `STATUS_TARGETS` entry that is not `host:port`, or a `STATS_URLS` entry that is not an `http` or `https` URL for a monitored host) stops the
server at start with a message.

## Status-only site

Operators who run their own Reticulum backbone can use this server for the status page alone,
without the rettui project pages. Set `SITE_MODE=status` (or `site_mode: status` at the top
of the config file; setting both is an error, and a value other than `full` or `status` stops
the server at start).

In `status` mode:

- `/` is the status page, and `/status` is the same page (an alias, not a redirect).
- `/join`, `/join-qr.svg`, `/downloads`, `/api/releases` and the files that belong to the
  project pages (`/index.html`, `/join.html`, `/downloads.html`, `/downloads.js`, `/copy.js`)
  answer 404. No release list is read, cached or fetched, so the server makes no requests to
  GitHub, and `RELEASE_REPOS` and `GITHUB_TOKEN` are not used.
- The menu and footer have no link to the project pages: the menu is "Status" and your own
  links, the footer is the site name and your own text.
- `/api/status`, `/api/stats`, `/api/incidents` and the public API (`/api/public/...`) work as in
  `full` mode, with the same privacy rules and logins.

### Branding: the `site:` section

The config file may have a `site:` section, in either mode, to give the status page a name and
look of its own. Every key is optional, and an unknown key is an error at start. Errors name the
key, never the value or the file content.

```yaml
site_mode: status
site:
  name: Acme Mesh              # 1 to 48 characters; shown in the title and the menu
  logo: site/logo.png          # png, jpg, webp or svg, up to 512 KiB, relative to this file
  description: Public entry points of the Acme backbone.   # up to 200 characters
  footer: Run by volunteers.   # up to 200 characters, plain text
  url: https://status.acme.example   # the https address of this site, no path (see below)
  links:                       # up to 6; http or https, no user name or password
    - { label: Join us, url: "https://acme.example/join" }
```

- Text is plain: no control or direction characters, no markup (it is escaped, never HTML).
- `logo` is read once at start. The file must be a regular file, and its first bytes must match
  its type (an SVG must start with `<svg`, and one with a script, a foreign object, an event
  handler, a `javascript:` link, or a `<use>`, `<animate>` or `<set>` element is refused; that check
  is only a first filter, and the real protection is the headers below). It is served at `/brand/site-logo` with its real type, `nosniff`, the
  site's strict policy and a `sandbox` on top, and the page only uses it as an `<img>`, so an SVG
  cannot run anything. It is also the page icon. Without `name` the logo is the brand; with both
  the name sits beside it. With Docker, mount the folder (`./site:/config/site:ro`) and write
  `logo: site/logo.png` in a config at `/config/config.yaml`.
- Without a `name`, `status` mode shows "Status" as the brand (not the rettui wordmark).
- In `full` mode the section changes the status page only: the name replaces the rettui name in
  the title and footer, your links are added to the menu, and `description` and `footer` are
  added. The home, Join and Downloads pages are the rettui project's and stay as they are. With no
  `site:` the pages are byte for byte what they were.
- `url` (or `SITE_URL` without a config file) is the https address of this server, with no path,
  user name, password, query or fragment. It does not change what a visitor sees: it is used for
  the links that must be absolute (the feed's own links now, the Open Graph tags below). It is
  also the address of passkeys (see "Passkeys"), where `http://localhost` is accepted too, for
  testing.
- The theme toggle, fonts and the strict CSP are unchanged: no inline script or style.

How it works: `status.html` stays a plain file. When the site is customised (status mode, or a
`site:` section), the server fills in its title, description, icon, menu, brand and footer once,
from the checked config, escaping every value (text and attributes), and serves that. A
template step was chosen over an `/api/site` JSON that `status.js` would read, because the page
is then correct on first paint, works without a second request, and the browser never handles
config text as anything but text. Without branding the file is served as it is.

A status-only compose file:

```yaml
services:
  status:
    build: .
    ports: ["8080:8080"]
    environment:
      DATA_DIR: /data
      CONFIG_FILE: /config/config.yaml    # holds site_mode: status, site: and your nodes
    volumes:
      - status-data:/data
      - ./config.yaml:/config/config.yaml:ro
      - ./site:/config/site:ro            # the logo: site/logo.png
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    restart: unless-stopped
volumes:
  status-data:
```

Without a config file (`SITE_MODE=status` and `STATUS_TARGETS`), there is no branding.

## Add a monitored host

Either set `STATUS_TARGETS`, for example
`STATUS_TARGETS=rns.rettui.dev:4242,other.example:4242`, or edit `DEFAULT_TARGETS` in
`lib/monitor.js`. Restart the server. A host removed from the list loses its saved history.

## Config file

Instead of `STATUS_TARGETS` and `STATS_URLS`, the nodes can be listed in a YAML file.
Set `CONFIG_FILE` to its path (`config.example.yaml` is a starting point). Setting
`CONFIG_FILE` together with `STATUS_TARGETS` or `STATS_URLS` stops the server at start, so
it is never unclear which one counts. Without `CONFIG_FILE` the variables work exactly as
before, and nothing needs to change for an existing deployment.

    nodes:
      - address: rns.rettui.dev:4242        # required, host:port
        name: Front door                    # optional display name, up to 48 characters
        stats_url: https://rns.rettui.dev/stats.json   # optional, same rules as STATS_URLS
        proxy_for:                          # optional: the nodes this one is a proxy for
          - front.rns.rettui.dev:4242
        count_own: false                    # optional, default false (see below)
        upstreams:                          # optional: external peers shown on the network map
          - name: Example hub               # 1 to 48 characters
            address: hub.example.org:4965   # optional, only shown, never checked
      - address: front.rns.rettui.dev:4242

The file is checked when the server starts, and any mistake stops it with a message that
never repeats a URL:

- Only `nodes`, `stats_token`, `stats_token_file`, `public_details`, `public_disk_figures`, `users`,
  `login`, `require_login` and `alerts` at the top level, and only `address`, `name`, `stats_url`,
  `stats_token`, `stats_token_file`, `proxy_for`, `count_own`, `public_details`,
  `public_disk_figures`, `require_login` and `upstreams` in a node; anything else is an error, as are repeated
  keys and wrong types.
- At most 64 nodes and a file of at most 64 KiB. The same host and port rules as
  `STATUS_TARGETS` apply, and the same URL rules as `STATS_URLS` (`https`, or `http` only
  for loopback and private addresses, no user name or password).
- Every `proxy_for` entry must be a listed node. A node cannot proxy itself, a node can have
  at most one proxy, and there can be no cycles. A proxy cannot itself be proxied (groups
  are one level deep).
- `upstreams` is a list of 1 to 8 maps with a `name` (1 to 48 characters, no control characters,
  each once per node) and an optional `address` (host:port); no other key is allowed. It can only be
  set in the file, on a node.
- The file is read as plain data only: no aliases or anchors that are used, no merge keys
  (`<<`), no custom tags and only one document.

In Docker, mount the file read-only and point `CONFIG_FILE` at it (see `compose.yaml`).
The image installs its runtime dependencies, `yaml` and `@simplewebauthn/server`, with
`npm ci --omit=dev --ignore-scripts`.

## Uptime history and incidents

Besides the 24 hours of checks, the server keeps a long-term record in `uptime.json` in
`DATA_DIR`:

- **Per node and day (UTC):** how many checks were up and how many there were, for the last 100
  days (the page shows 90). A day's percent is rounded down to a tenth, so only a day with no
  failed check reads 100.
- **Incidents:** a node is down when 2 checks in a row fail, and up again when 2 in a row work, so
  one dropped probe is not an incident. An incident starts at the first failed check of the run and
  ends at the first good check of the run that closed it; while it lasts its end is `null` and it
  is "ongoing". The last 50 incidents per node are kept, and 1000 over all nodes.
- The file is written to a temporary file and renamed (readable by the owner only), is checked
  entry by entry when loaded, and a missing, damaged or oversized (over 2 MiB) file means
  starting empty. An incident that is open when the server restarts stays open and is not
  announced again. A node removed from the config loses its record, like its history. Nothing is
  backfilled: the bar fills in from the day this version is deployed.

`/api/status` has, for each host, `uptime90` (`{percent30, percent90}`, `null` without data),
`days` (90 numbers, oldest first and today last: the percent up that day, or `null` for a day
without checks). The incidents are not in it: `/api/incidents` answers
`{generatedAt, incidents: [{host, name, start, end, seconds, ongoing}]}`, times as ISO text,
`end` `null` while ongoing and `seconds` counted to now for an ongoing one. Both are as public as
up and down already is: no `public_details` or `require_login` setting changes them, and they hold
nothing from a node's stats.

On the page, a cell is green only on a day with no failed check (100%), yellow and shorter from 95%, red and shorter below
that, and short and dim with no data, so the bar does not rely on colour. Each cell's title
gives its date and percent, and the bar has a text label with the same figures.

## Alerts

The server can send a message when a node goes down and when it is up again. It is off unless the
config file has an `alerts` section (there is no environment variable for it, because it carries
secrets). The messages are plain, for example `Front (front.rns.rettui.dev:4242) is down since
12:03 UTC.` and `Front (front.rns.rettui.dev:4242) is back up after 5m 00s (down since 12:03 UTC).`

    alerts:
      channels:
        - type: webhook
          url: https://hooks.example.org/rettui   # https, or http for loopback and private hosts
          format: generic                         # generic (default), ntfy, discord, slack or apprise
          secret_file: secrets/hook.secret        # optional, or secret: for the value itself
        - type: email
          host: smtp.example.org
          port: 587                               # default 587 (starttls) or 465 (tls)
          security: starttls                      # starttls (default) or tls (SMTPS)
          username: alerts                        # optional; then password_file is needed
          password_file: secrets/mail.password
          auth: plain                             # plain (default) or login
          from: status@example.org
          to: [ops@example.org]
      events: [down, recovered]                   # default both; announce_queue is added by listing it
      announce_queue_samples: 3                   # default 3 (1 to 100): see "Announce queue" below
      cooldown_minutes: 15                        # default 15
      repeat_minutes: 0                           # default 0: no reminders

- **When:** one alert when an incident opens (the same 2 failed checks as above) and one when it
  closes. A node that goes down again within `cooldown_minutes` of its last "down" alert is not
  announced again, and neither is the recovery of that incident, so a flapping node does not send
  a stream of messages. If that node then stays down, the held-back "down" alert is sent as soon
  as `cooldown_minutes` have passed since the last one, so a node that is down is always announced
  in the end. With `repeat_minutes` (0, or 5 and more) a node that stays down gets a
  reminder that often. A server that starts while a node is down announces it only if it is a new
  incident: one that was open before the restart is not announced again, but it gets its
  reminders (counted from the first check after the restart).
- **Sending:** alerts wait in a queue of at most 100 (the oldest is dropped if it is full) and are
  sent in the background, so a slow or dead channel never holds up the checks. A failed send is
  tried up to 3 times, after 5 and 30 seconds, then given up; while it waits it holds no sending
  slot, so a dead channel does not hold up the others. A client error from a webhook (such
  as 404), a refused mail address and a wrong mail password are not tried again. Failures are logged
  as `alert: webhook channel 1 failed (http 500), ...`, never with an address, secret or answer.
  Alerts only come from the monitor: there is no endpoint to send or test one, and nothing a
  visitor sends starts a request.
- **Webhook:** a POST with a short timeout (10 seconds), no redirects followed, and the answer is
  never read. The URL follows the `stats_url` rules: `https`, or `http` only for loopback and
  private addresses, and no user name or password. A URL that holds a secret in its path (as chat
  services do) is treated as one: it is never logged or repeated in an error. The generic body is
  `{event, host, name, message, since, recoveredAt, sentAt, durationSeconds}`, with `event`
  `down`, `still_down` or `recovered`. With `secret` or `secret_file` (16 to 256 printable
  characters) each request has `X-Rettui-Timestamp` (unix seconds) and `X-Rettui-Signature:
  sha256=<hex>`, the HMAC-SHA256 of `<timestamp>.<body>` (the exact body bytes), so the receiver
  can check who sent it and when. **Reject a timestamp more than 5 minutes from your clock**, or a
  captured request could be sent again later. In Node.js:

      const ts = req.headers['x-rettui-timestamp'];
      const want = 'sha256=' + crypto.createHmac('sha256', secret).update(`${ts}.${rawBody}`).digest('hex');
      const ok = Math.abs(Date.now() / 1000 - Number(ts)) <= 300 &&
        req.headers['x-rettui-signature']?.length === want.length &&
        crypto.timingSafeEqual(Buffer.from(req.headers['x-rettui-signature']), Buffer.from(want));
 The other formats send what that service expects:
  `ntfy` the text as the body, `slack` `{"text": ...}`, `discord` `{"content": ...}`, and `apprise`
  `{"title": ..., "body": ..., "type": ...}` (see below). The signature headers are also sent to
  Apprise, which ignores them.
- **Email:** a small built-in SMTP client (no dependency). The connection is always encrypted and
  the server's certificate is always checked: `tls` is SMTPS from the first byte, `starttls`
  upgrades the connection and refuses to go on if the server does not offer it, or if anything came
  with its "go ahead" before the encryption started (a reply planted there, `starttls failed`). `username` with
  `password_file` logs in (`AUTH PLAIN` or `LOGIN`), after the encryption is up. A line break in
  any address, name or subject is refused, never cleaned. Replies and the message are capped, and
  the whole send has a 20 second limit.
- **Secrets:** `secret_file` and `password_file` are read once at start, relative to the config
  file (a file other users can read gets a warning), and held in memory only. They are never
  logged, never in an `/api` answer, never in `uptime.json`, and never repeated in an error.
- **Checked at start:** unknown keys, wrong types, more than 4 channels, more than 5 recipients,
  too-long strings and bad addresses stop the server with a message. Alerts are sent to the
  addresses in this file only.

**LXMF.** The website server has no Reticulum stack, so it cannot send an LXMF message itself.
[`bridges/lxmf`](bridges/lxmf/README.md) is a small bridge that does: it receives this webhook
(checking `X-Rettui-Signature` and the timestamp), and sends the `message` field as an LXMF message
to the addresses you list, with a Reticulum entry point or a propagation node. It has its own
Dockerfile and a Compose snippet, and it is not part of the website image; a built image is published
as `ghcr.io/rettui-dev/lxmf-bridge` (tags `dev`, `latest` and release versions), so you can pull it
instead of building it. Any other service that
accepts a webhook can be reached the same way, with a bridge of your own.

**Other services (Telegram, Matrix, Pushover and so on): Apprise.** [Apprise](https://github.com/caronc/apprise)
sends one message to many services, and its API container
[`caronc/apprise-api`](https://github.com/caronc/apprise-api) takes it over HTTP, so it can be the
target of a webhook channel with `format: apprise`. (shoutrrr is not an option: it is a command line
sender with no HTTP listener, so nothing can post a webhook to it.) The container holds the
notification URLs, which carry the services' secrets, so they never go in this config file. The
channel's `url` is the container's `/notify/<key>` endpoint, where `<key>` is a name you choose
when saving the URLs. What is sent, as the Apprise API documents it (README of `caronc/apprise-api`,
read on its `master` branch): `POST /notify/<key>` with `Content-Type: application/json` and
`{"title": ..., "body": ..., "type": ...}`, where `type` is one of `info`, `success`, `warning`,
`failure`. Here `down` and `still_down` are `failure`, `recovered` and a cleared announce queue are
`success`, and a full announce queue is `warning`; the title is `[rettui] Front is down` and the
body is the same text as the other formats. Without a `tag` Apprise sends to every URL saved under
the key.

    alerts:
      channels:
        - type: webhook
          format: apprise
          url: http://172.28.0.20:8000/notify/rettui   # the fixed IP of the apprise container, see below

A compose snippet, from the image's own documentation (the hardening options are the ones it
lists for its "more hardened configuration"). It was not run here (no Docker in the build
environment). The container listens on port 8000 and keeps what you save under `/config`:

    services:
      apprise:
        image: caronc/apprise:latest
        user: "1000:1000"             # the owner of ./apprise-config
        read_only: true
        security_opt: ["no-new-privileges:true"]
        cap_drop: [ALL]
        environment:
          APPRISE_STATEFUL_MODE: simple
          APPRISE_WORKER_COUNT: "1"
        volumes:
          - ./apprise-config:/config
        tmpfs: [/tmp]
        networks:
          alerts:
            ipv4_address: 172.28.0.20   # a private address: the website accepts http for it
        # No "ports:": only the website, on the same network, can reach it.
      # ... the website service, with `networks: [alerts]`
    networks:
      alerts:
        ipam:
          config:
            - subnet: 172.28.0.0/24

To save a set of notification URLs under the key `rettui`, open the container's page (from the
host, for example by temporarily publishing the port on `127.0.0.1` or with `docker compose exec`)
and add them in its configuration manager, or post them to its API:

    curl -X POST -d 'urls=tgram://BOT_TOKEN/CHAT_ID,matrixs://...' http://172.28.0.20:8000/add/rettui

The URL forms for each service are in the Apprise documentation (<https://appriseit.com>). To try it:
`curl -X POST -H 'Content-Type: application/json' -d '{"title":"test","body":"hello","type":"info"}' http://172.28.0.20:8000/notify/rettui`.

- **Plain http needs an IP.** The website allows `http` only for loopback and private IP
  addresses, and a compose service name such as `apprise` is neither, so give the container a
  fixed address on a compose network, as for the [LXMF bridge](bridges/lxmf/README.md), or put it
  behind `https`. The rule is not relaxed for single-word host names: a name can be resolved to
  anything by whoever controls the network's DNS, while a fixed private address is only that.
- **No login in the URL.** The URL may not hold a user name or password, and this server sends no
  `Authorization` header. The Apprise API has no login unless you turn it on
  (`APPRISE_AUTH_REQUIRED`), so leave it off and keep the container on a private network with no
  published port, as above. The key in the URL is then the only thing that selects the URLs; it is
  treated as a secret like any URL path (never logged). If the container must be reachable from
  elsewhere, put an `https` reverse proxy with its own access control in front.
- **Not verified here:** only the request shape above was checked against the documentation. No
  Apprise container was run, so the compose snippet and the delivery to any service are untested.

LXMF has its own bridge, so a webhook channel for Apprise and one for the
[LXMF bridge](bridges/lxmf/README.md) can be listed side by side: an alert goes to every channel.

**Announce queue.** Off unless `announce_queue` is listed in `events` (the default stays
`[down, recovered]`). A rettui node reports the announces waiting to go out in `stats.json`
(`announce_queue`, new in rettui 2.1.0: a node on an older version never reports it, and so never
alerts), and says itself when one interface's queue is at its limit (`full`, 4096 per interface).
After `announce_queue_samples` samples in a row with `full` true (default 3, 1 to 100; a sample is
one successful stats fetch, every 30 seconds) one alert goes out, `<node> has a full announce queue
(4096 waiting): an interface is at its limit and drops new announces.`, and one more when it clears.
A failed stats fetch breaks the run: "in a row" needs every sample. The cooldown works as for
down alerts: a queue that fills again within `cooldown_minutes` of the last "full" alert is not
announced again, nor its clearing; if it then stays full, the held-back alert goes out once the
cooldown has passed. "Was full for" counts from the first full sample. The generic webhook `event` is `announce_queue_full` or
`announce_queue_cleared`. There are no reminders for it. A node without a `stats_url` can never
send it, so the server prints a warning at start for each such node when `announce_queue` is listed.

    alerts:
      events: [down, recovered, announce_queue]
      announce_queue_samples: 3

On SIGINT or SIGTERM the server writes the history and the uptime once more, waiting for any save
that is running, before it exits. It also waits for the audit lines and the failures summed up so
far. Changes to the user store need no waiting: each is on disk before it is answered.

## What is public

With users in the config file, some of what follows can also be kept for logged-in visitors;
see "Logins".

- **`public_details`** (default `true`): when `false` a node has no Details button, and
  `/api/stats` answers 404 for it, the same as for an unknown host. Its summary on the page stays.
  A node whose details are private is also left out of its proxy's combined view: its graphs,
  its place in the node list, and the totals, node counts and "not reporting" names of that
  view (the exact peer count is then a range, as it was worked out with all nodes). The group
  line on the status list itself still counts every node, because the node rows are there too.
  Set it at the
  top of the config file for every node, or on a node to override. With the environment variables,
  `PUBLIC_DETAILS=false` sets it for all nodes (not with `CONFIG_FILE`).
- **`public_disk_figures`** (default `false`): the free and total space of a node's disk say a lot
  about a machine. A node only sends them to a website that has a token, and even then the website
  publishes only a level (`ok`, `high` from 75% used, `full` from 90%) and the used share rounded
  to 5, never a byte figure of the file system. Set `public_disk_figures: true` (or
  `PUBLIC_DISK_FIGURES=true`, or per node) to publish the exact free and total space, the exact
  share, and the free-space graph. Without it there is no disk graph. The node's data size is
  public on the node already and is shown either way. A node without a token has no disk level.
  A group shows the fullest disk by level, and the exact least free space only for nodes that
  publish it.
  The history file (`stats-history.json`) keeps the exact free space of the disk at rest, whatever
  this option says, and it is not purged. Setting `public_disk_figures: true` later therefore
  shows the free-space graph for the time already recorded, not only from then on. Keep the data
  directory private, and delete that file if you do not want that history.

## Public stats API

For others to build dashboards. Version 1 is stable: fields are only ever added, and a change
that removes or renames one would be `/api/public/v2/...`.

- `GET /api/public/stats` (GET and HEAD only; anything else is 405).
- `GET /api/public/incidents`: the same incidents as `/api/incidents` (up to 100, newest first).

Both work in `full` and `status` mode, with the usual security headers plus
`Access-Control-Allow-Origin: *`, which no other route has. `Cache-Control: public, max-age=30`,
and a strong `ETag` (made without the `generated` time, so it stays the same while nothing changes); `If-None-Match` gets a 304. The answer is built from memory at most every 10
seconds, whatever the number of requests, and the query string is ignored.

**What it shows.** Exactly what a visitor who is not logged in sees on the status page. It is
built from the same anonymous view, with only the fields below copied. With users in the config,
it never depends on the cookie: it reads none, sets none and always shows the anonymous view.
`require_login` sections are left out (`propagation` and `disk` are then `null`, or lose
those counters), and `public_disk_figures` decides whether `disk` has byte figures. It never has
tokens, peer lists, hashes, versions, upstreams, stats URLs or paths. A node with no stats URL, or
whose stats are old, has `null` for its numbers. With 64 nodes it is about 55 KB.

`GET /api/public/stats`:

```
{
  "version": 1,
  "generated": ISO time,
  "nodes": [ {
      "name": text (the configured name, else the host),
      "address": "host:port",
      "role": "node" | "proxy",
      "status": "up" | "down" | "unknown",
      "up": true | false | null,
      "connectMs": number | null,            // last TCP connect time, null when down
      "lastChecked": ISO time | null,
      "uptime30": percent | null,  "uptime90": percent | null,
      "clients": number | null,
      "interfaces": { "total": n, "online": n } | null,
      "peersHeard": { "total": n, "lxmf": n, "nomad": n, "propagation": n } | null,
      "announcesLastMinute": number | null,
      "propagation": { storedMessages, storedBytes, storageLimitBytes, peersConnected,
          peersTotal, peersAlive, peersStatic, peersAuto, peerLimit, staticPeers,
          autopeerDepth, messagesReceived, messagesServed, messagesSentToPeers,
          messagesReceivedFromPeers, messagesOfferedToPeers, unhandledMessages,
          unhandledDistinct: number | null,
          autopeer?: boolean | null } | null,   // keys locked by require_login are absent
      "disk": { "level": "ok" | "high" | "full" | null, "usedPercent": number | null,
          "totalBytes"?: n, "freeBytes"?: n } | null,  // bytes only with public_disk_figures
      "announceQueue": { "queued": n | null, "limit": n | null, "full": bool, "fullest": n | null } | null,
          // null when the node reports none (needs rettui 2.1.0); full: one interface is at its limit
      "proxyFor": ["host:port", ...],
      "proxiedBy": "host:port" | null,
      "group": null | {                       // a proxy's combined view
          "countOwn": bool, "nodes": n, "reporting": n, "partial": bool,
          "clients": n | null, "interfaces": { "total": n, "online": n } | null,
          "announcesLastMinute": n | null,
          "peersHeard": { "exact": bool, "total"|"lxmf"|"nomad"|"propagation": { "min": n, "max": n } } | null,
          "propagation": { the same counters, added up, plus "nodes" } | null,
          "disk": { "nodes": n, "worstLevel": text | null, "worstUsedPercent": n | null,
              "lowestFreePercent"?, "lowestFreeBytes"?, "lowestFreeTotalBytes"? } | null } } ],
  "network": {
    "overall": "up" | "degraded" | "down" | "unknown", "checkedAt": ISO time | null,
    "intervalSeconds": n, "nodes": n, "up": n, "down": n, "unknown": n, "reporting": n,
    "proxies": n, "proxiesUp": n, "proxiesDown": n,
    "clients": n | null, "interfaces": { "total": n | null, "online": n | null },
    "announcesLastMinute": n | null,
    "peersHeardSum": { "total": n | null, "lxmf": ..., "nomad": ..., "propagation": ... }
  }
}
```

In `group`, peers heard is a range from the busiest single node (`min`) to the sum (`max`),
and one number when `exact` is true (see "Proxies and groups"). Each entry of `nodes` has a
`role`, `"proxy"` (it has `proxy_for`) or `"node"`.

In `network`, a proxy is not a node: `nodes`, `up`, `down`, `unknown` and `reporting` count the
entries with role `node` only, and `proxies`, `proxiesUp` and `proxiesDown` count the proxies.
A standalone node with no proxy is a node. `overall` still follows every entry, the proxies too,
because a proxy that is down closes the door for visitors. In the sums, every node counts once:
the nodes behind a proxy through the proxy's `group`, any other node through its own numbers,
and a proxy's own numbers only when it has `count_own: true` (inside its `group`), never twice.
`peersHeardSum` is an upper bound, as one peer heard by two nodes counts twice. `reporting` is
the number of nodes with fresh stats.

Behaviour change on dev, before any release: `network.nodes` used to count the proxies too, and
`up`, `down`, `unknown` and `reporting` followed it. The API is new and unreleased, so the
version stays `1`.

`GET /api/public/incidents`:

```
{ "version": 1, "generated": ISO time,
  "incidents": [ { "address": "host:port", "name": text, "start": ISO time,
                   "end": ISO time | null, "seconds": n, "ongoing": bool } ] }
```

## Logins

Some numbers can be kept for people with an account. With no `users` in the config file and none
in the user store (`users.db`, see "Accounts and second factor") there is no login at all and
the page and API are exactly as without this feature: nothing is locked, there is no login button,
and `/login` does not exist. Any users at all need the user store key (see "The user store
key"). Users in the config file need the config file. Users in the user store work with the
config file or with the environment variables alone. With a config
file, its `login` settings and `require_login` apply to them as to users in the file. With the
environment variables alone there is no `login` section or `require_login`: every section is
locked, the session settings keep their defaults, and the trusted proxies are set with
`LOGIN_TRUSTED_PROXIES` (see "Behind a reverse proxy").

    users:
      - name: alice                  # 1 to 32 letters, digits, . - _; matched without regard to case
        password_hash: '$argon2id$v=19$m=19456,t=2,p=1$...$...'
        role: admin                  # optional: admin, manage or viewer (the default)
    login:                           # optional, these are the defaults
      idle_timeout_minutes: 60       # a session ends after this long without a request
      max_age_hours: 12              # and this long after the login, whatever happens
      max_sessions: 1000             # with more, a session of whoever has the most ends
      trusted_proxies: []            # see "Behind a reverse proxy"
    require_login: [details, storage, peers, disk, versions]   # the default once there are users
    nodes:
      - address: rns.rettui.dev:4242
        require_login: []            # a node can override the rule, like public_details
                                     # (this does not make its logs public, see "Node logs")

**Making a hash.** `npm run hash-password -- --name alice` asks for the password twice without
showing it and prints the hash and a line to paste under `users:`. The name in that line is in
quotes, because YAML reads a bare `123`, `true` or `null` as a number, a boolean or nothing,
and the config needs text; quote a name you type yourself for the same reason. It also reads a password piped
to it (`printf '%s' "$PW" | node scripts/hash-password.js --name alice`; one final line break is
dropped), but never takes one as an argument, where it would land in the shell history. In Docker:
`docker compose run --rm -it website node scripts/hash-password.js --name alice`. The hash is
Argon2id with a random 16-byte salt and the OWASP minimum costs (`m=19456,t=2,p=1`); `--memory`,
`--passes` and `--parallelism` raise them. Only `argon2id` version 19 hashes are accepted, with
at least those costs and at most `m=65536,t=16,p=16`; anything else stops the server at start
(the message never repeats the hash). The memory cap is 64 MiB because at most three checks run
at once (two for sign ins from outside, one more kept for signed-in users and known devices), so
logins never take more than 192 MiB. The config file holds hashes, not passwords, but keep it
private anyway: its hashes are never peppered (the server cannot rewrite the file, and a hash
with a `keyid` in it stops the server at start, "hashes in the config file cannot be peppered").
To give an admin the pepper, move them into the user store (see "Moving users out of the config
file").

**What is locked.** `require_login` lists sections, at the top for every node or on a node to
override it. Without a rule, once there are users (in the config file or in the user store), all of
them are locked. A rule that names a section while there are no users anywhere stops the server at
start, and so does a `login` section.

| Section    | What a visitor without a login does not get |
| ---------- | ------------------------------------------- |
| `details`  | the Full details view and its graphs (`/api/stats` answers 401), and the node's place in a proxy's combined view |
| `storage`  | the message store of a propagation node: stored messages and size, message counters, the backlog waiting to send to peers, and their graphs |
| `peers`    | its peered propagation nodes: alive and total, static and automatic, limit, auto-peering, the peered nodes it lists and their table in the Full details, and their graph; also the messages sent to, received from and offered to peers, and the peer message flow graph (these go with `storage` too) |
| `disk`     | the disk level and share, free space, and data size; also the size of the message store (its bytes and graph), which on a propagation node is most of the data size |
| `versions` | the rettui version a node runs, and the versions seen |

Up or down, the check bar and uptime, clients, peers heard, traffic, announces, interfaces and how
long a node has been running stay public. The server takes the locked numbers out of
`/api/status` and `/api/stats` before they are sent; the page only shows what it got.
A visitor who is not signed in is not shown what needs a login: no locked placeholder, no greyed
tab, no "log in" box in a row. The Logs tab, the Full details button of a node whose details are
locked, and the sections above are left out altogether. Where something is hidden, the status page
says so once, in one line under the banner ("Some details are only shown to signed-in users." and a
Sign in link), and the Overview of the details says the same; a site or visitor with nothing hidden
gets no line. The logs of a node are never said to exist to a visitor who may not read them, so they
are not counted as hidden. A proxy's group line leaves out a sum
(message store, peered nodes, disk) as soon as one of its nodes, or the proxy, has that section
locked, since the sum would give the node's number away. A node whose details are locked is left
out of the combined view, as with `public_details: false`. `public_details: false` and
`public_disk_figures` still apply to logged-in users: a login shows what is locked, never what
is private.

With users, `/api/status` has `viewer` (`{name}`, `null` without a login) and each host has
`locked`, the sections this visitor cannot see (empty once logged in); a detail answer with
something left out has `locked` too. Both answers then carry `Cache-Control: private, no-store`
and `Vary: Cookie`, so no shared cache keeps one visitor's answer for another.

**The Sign in button.** Every page (home, status, join, downloads) has a Sign in button at the right end
of the header, after the Theme button; on a phone it stays in the header row, not in a menu. It
appears only when the site has users (`/api/session`), and it needs JavaScript. It opens a dialog
with name and password, which posts to `/login`, and the visitor stays on the page they were on.
Signed in, the button reads Sign out and the name sits beside it; the status page then fetches its
numbers again. Without a config file with users there is no button. The button and its dialog are
built by `public/account.js` (no inline script or style), take keyboard focus like any button, and
use the same colours and focus ring in the dark and light themes.

**How the login works.** The page posts the form to `/login`. It answers 200 with a session
cookie, `__Host-rettui_session`: a random 256-bit id, `HttpOnly`, `Secure`, `SameSite=Strict`,
`Path=/`. Every login gets a new id, and an id sent with the login is ended. `/logout` ends the
session. Sessions are kept in memory only. An open status page refreshes itself every 15 seconds,
so it keeps its session alive until `max_age_hours` is reached. Every request checks that the
user still exists and takes the role they have now: a session of a user who was removed ends at
once. One user has at most 20 sessions; a 21st sign in ends that user's own least used one. With
`max_sessions` reached in all, a new sign in ends the least used session of the user who has the
most, so one account signing in over and over never signs anyone else out.

- A wrong name and a wrong password get the same 401 and the same message. An unknown name is
  checked against a stand-in hash with the costs of one of the users. The costs are picked from
  the name among the different costs the users have, with a key derived from the user store key,
  so the same unknown name always takes as long as one real user's wrong password, also after a
  restart: its time does not tell whether the name exists. The pick only changes when a set of
  costs comes or goes (a user with new costs, or the last one with some), not with every user. A
  website user whose password hash needs a key version the server was not given gets the same
  answer as a wrong password, after a hash of the same costs, and the server logs an error line
  naming the user and the version (at most once a minute per user).
- A password over 1024 bytes, or a name over 64 characters, can never be right: it gets the same
  401 at once, without a hash, and counts nowhere. It is not a guess, so sending many of them
  holds nobody back.
- **Known devices.** Every sign in that works (the password, and the second step when two-step
  sign-in is on) sets a second cookie, `__Host-rettui_device`: a random 128-bit id, `HttpOnly`, `Secure`,
  `SameSite=Strict`, `Path=/`, for 180 days. The server keeps only its SHA-256, with the user (at
  most 10 per user; past that the one used least recently is forgotten), and when each was first
  and last used (the times of sign ins are written to the user store at most once a minute per
  user). A browser that sends it with the right name is a known device: it is never paced
  or refused because of other people's failures (below), and has its own place in the check
  queue. It is never a sign in by itself: the password, and the code, are needed as always. Its
  own sign ins are paced: three that work at once, then one every 3 seconds; past that the answer
  is 429 ("Too many sign ins from this browser right now"), before the password is checked. When
  the code step finds a different device cookie than the password step did (or none), the
  browser is a new device and gets a new id. A
  password change forgets every known device but the browser that made it; turning two-step
  sign-in on or off and signing out other sessions do the same, and removing a user forgets all
  of them. The account page lists them (see "Known devices").
- Failed logins are counted in these ways:
  - **For a name from one address.** Five are free; after that each one doubles a wait, up to 15
    minutes, for that name from that address only. During it the answer is 429 with
    `Retry-After`, without trying the password. A login that works clears this count.
  - **For an address, over every name.** Twenty are free, then the same doubling wait. An IPv6
    address counts by its /64, and also for its /56 (60 free) and its /48 (200 free), so a whole
    network does not get the free tries of every /64 in it. A login that works only halves these
    counts, so an address cannot wipe its own failures by signing in to an account of its own.
  - **For a name, from every address together.** Tries at one name are paced: 5 at once, then one
    a second. A try past that waits for its turn, at most 4 seconds; one that would wait longer is
    refused with 429 and `Retry-After` ("Too many sign ins for this name right now"), without a
    hash. So nobody gets more than about 3600 guesses an hour at one name, from however many
    addresses. It is the same for every name, known or not. A try that is turned away before its
    password is checked (503, or one of the waits above once its turn came) gives its turn back,
    and a try that would get 503 at once is answered before it takes one, so requests that cost
    the sender nothing cannot keep a name paced.
  - **For a known device.** A known device skips all three: its own failures count in a wait of
    its own (five free, then the same doubling), and still count for its address.
  A failure is forgotten an hour after the last one. Once the free tries are used up, a login
  waits for the checks already running for the same name and address (or address), so a burst
  sent at once gets no more tries than one sent one by one; more than 8 waiting for one of them
  get 503. At most 10000 keys are remembered in each count. When that many are, a new key makes
  room by forgetting the one with the fewest failures (the oldest of those): it is never refused
  because the count is full, and a key with many failures is only forgotten once every other key
  has as many. Wrong passwords asked while signed in count in a count of their own (see "Changes
  need a recent sign in"). Failures are summed up in `failures.log` (see "Audit log").
- Each check takes about 19 MiB of memory (more with higher costs, at most 64 MiB). For sign ins
  from outside at most 2 run at once and 8 wait, and one address has at most 2 of those 10
  places; past that the answer is 503 with `Retry-After: 2`, rather than running out of memory.
  One more check may run for passwords asked while signed in (and new password hashes) and for
  known devices only, each with a queue of its own (4 places, 2 per session or device). They run
  in that place, and in a place of the sign ins from outside only while none of those is
  waiting. So a flood from outside never holds back a signed-in user or a known device, and
  signed-in users and known devices never hold back a sign in from outside for more than that
  one place. A 503 does not count as a failed login.
- `/login`, `/login/code`, `/login/passkey` and `/logout` only take `application/x-www-form-urlencoded` (else 415),
  at most 4 KiB, or 8 KiB for `/login/passkey` (else 413), with the header `X-Rettui-Request: 1`, and only from the page itself:
  `Sec-Fetch-Site` must be `same-origin`, or, from a browser too old to send it, `Origin` must
  name the host the request was sent to (else 403). A form on another site cannot send the
  header.
- Passwords, hashes and device ids are never logged.

**Behind a reverse proxy.** The cookie is always `Secure`, so the login only works over HTTPS
(browsers make an exception for `localhost`). Put the server behind a reverse proxy that
terminates TLS. The server reads `X-Forwarded-Proto` for one thing only: when a trusted proxy (see
below) says `https` (the last value, when there are several), the answer carries
`Strict-Transport-Security: max-age=31536000; includeSubDomains`, so browsers use https for the
site, and its subdomains, for a year. Over plain http, or when anyone else sends the header, it is
never sent. Without trusted proxies, set it at the proxy instead. `includeSubDomains` means the
browser holds every subdomain of the site's host to https as well, for a year from its last visit,
and it cannot be taken back sooner from the server: turn it on only when every subdomain is served
over https. The proxy must pass the
`Host` header through (Caddy does; with nginx, `proxy_set_header Host $host;`) for browsers that
do not send `Sec-Fetch-Site`. Without trusted proxies every request seems to come from the
proxy, so all visitors share one address for the failed-login waits. List the proxy's address in
`login.trusted_proxies` in the config file, or, with users in the user store and no config file, in
the environment variable `LOGIN_TRUSTED_PROXIES` (comma separated, for example
`LOGIN_TRUSTED_PROXIES=127.0.0.1,::1`). At most 16 entries, each an IP address or a network in
CIDR notation, mixed as needed: `172.22.0.0/16`, `10.0.0.0/8`, `fd00:1::/32`. Use a network when
the proxy's address changes, as a container's does on a Docker network. The client address is
then taken from `X-Forwarded-For`, from the right, skipping trusted proxies, whether listed as an
address or inside a listed network. An IPv6 address may be written in any form
(`0:0:0:0:0:0:0:1` is `::1`), and an IPv4-mapped one (`::ffff:172.22.0.5`) counts as IPv4, so it
falls in `172.22.0.0/16`. Bits after the prefix are cleared (`172.22.9.5/16` is `172.22.0.0/16`),
and `/32` or `/128` is the single address. A wrong entry (a prefix over 32 or 128, a space, a
host name) stops the server at start with a message naming the entry.

Only list addresses and networks that nothing untrusted can connect from: anything inside a
trusted network can write its own `X-Forwarded-For` and choose the address its failed logins
are counted against. `/0` trusts every address and is refused. A network shorter than `/8` for
IPv4 or `/16` for IPv6 (so `fd00::/8` too) is allowed, but the server warns at start with a line
that starts with `WARNING:`; prefer the proxy's own subnet. IPv4 addresses are matched as
IPv4-mapped IPv6 (`::ffff:a.b.c.d`), so an IPv6 network that holds all of `::ffff:0:0/96`, such
as `::/64` or `::/80`, would trust every IPv4 client and is refused like `/0`.

A hop in `X-Forwarded-For` with a port, `192.0.2.1:5678` or `[2001:db8::1]:443`, is read as the
address alone; `[2001:db8::1]` without a port too. Any other hop that is not an IP address makes
the server take the proxy's own address for that request, and it logs one warning that starts
with `WARNING:`: set the proxy to send plain client addresses. If a request with `X-Forwarded-For`
comes from a loopback or private address that is not listed, the server logs one warning that
starts with `WARNING:` and names both settings.

**Limits.** Everything is in one process and in memory: sessions end when the server restarts
(everyone has to log in again), and running several copies behind a load balancer does not
share sessions or failed-login counts. Users can turn on a second factor (an app code, or passkeys) on their
account page, and website users can change their password there (see "Accounts and second
factor"); there is no account lockout beyond the wait.

- **Guessing against lockouts.** The waits per name and address and per address only hold back
  that address, so nobody can lock someone else out by knowing their name. The pace of a name is
  the one that holds back everyone: about one guess a second at one name, however many addresses
  send them (about 3600 an hour). While it is used up, a browser that is not a known device gets
  429 for that name, the owner's new browser too; a known device of the owner still signs in at
  once. So sign in from your usual browser, keep a strong password (the account page asks for at
  least 12 characters), and turn on the second factor (see "Accounts and second factor"), which
  is the real defence. Pick names that are not easy to guess, such as not `admin` or your public
  handle.
- **Flooding.** Someone sending logins from many addresses at once can fill the 10 places of the
  check queue for sign ins from outside (2 per address); a real login from a new browser then gets
  503 and gets in when it tries again a moment later. Signed-in users and known devices have a
  place of their own and are not held back, and they cannot fill the outside places either.
  Sending logins needs no account, so a large enough
  set of addresses can always fill the outside places.
- **Behind a proxy without trusted proxies** every visitor shares the proxy's address, so the
  per-address counts above are shared too, and one visitor's failures can hold back another
  (known devices are not held back by them).
- **`require_login` only covers this website.** It takes numbers out of what this server sends;
  it does nothing to the nodes. A node's `stats.json` answers whoever fetches it, so anyone who
  can reach a `stats_url` reads the locked numbers from the node itself. For numbers that must
  stay private, make each `stats_url` reachable only by this website (a private network, a
  firewall rule, or a reverse proxy in front of the node that asks for a secret).

The Docker image is built from an exact Node.js 24 release, pinned by digest
(`FROM node:24.22.3-alpine@sha256:...` in the `Dockerfile`), so every build starts from the same
image. It moves only when the `Dockerfile` is changed: to take a newer Node.js 24 (at least 24.7),
change the version and the digest together (`docker buildx imagetools inspect
node:24.x.y-alpine` gives the digest).

## Accounts and second factor

Everyone who can sign in has an account page, `/account`: the name in the header links to it once
signed in. It shows the name, the role, the last sign in, where the account is signed in (the sessions in
this server's memory, without addresses) and its known devices, and has the password and the
second factor: an app code, passkeys, or both (see "Passkeys"). The recovery codes work with
either.

**Where users live.** Users come from two places:

- **The config file** (`users:`, see "Logins"), as before. These users keep working exactly as
  they did. Their name, password and role are set in the config file only; the account page
  says "Managed by config" and has no password change. Each may have a `role`: `admin`,
  `manage` or `viewer` (the default when it is left out).
- **The user store**, `users.db` in `DATA_DIR`, for users made on the website's Users page or
  with `scripts/users.js` (see "Managing users"). Each has a name, a role, an Argon2id password
  hash like those in the config file (peppered, see "The user store"), the times it was made and
  last signed in, its second factor, and `mustChangePassword` while the password is one an admin
  set.

When a name is in both, the one in the config file is used and the server logs a warning at
start; the one in the store cannot sign in, and is left as it is. A user in the config file can
still turn on a second factor: it is kept in the store under the user's name, apart from the
website users, with nothing else. Roles are shown on the account page. `admin` opens the Users
page (see "Managing users"); nothing else depends on the role yet.

**The store.** `users.db` is a SQLite database (see "The user store" for the key, backups and
the volume it needs). Every change is one short transaction, written to disk before it is
answered, so a crash never leaves half a change. A store that cannot be read (damaged, made by a
newer version, a record that makes no sense, a table, column, trigger or view this version does
not make, or a key that does not fit) stops the server at start with a message that says why,
and the file is left as it is: a broken store never becomes an empty one, which would drop
everyone's second factor. Fix or move the file (or give the right key) and start again. The file
is made with mode 0600, and a store that other users can read gets a warning at start. A link in
place of `users.db`, `users.db-wal` or `users.db-shm`, or anything else that is not a plain file,
is refused before the store is opened. Deleted rows are overwritten in the file (SQLite's
`secure_delete`), not left in its free space. SQLite keeps the latest changes in `users.db-wal`
for a while, old pages included; so after a user is deleted, or a password, TOTP secret or
recovery code is replaced or used, the server also empties `users.db-wal` into `users.db` (a
checkpoint, at most once a second, and tried again later when another program is reading the
store just then). The sqlite_stat tables that SQLite's `ANALYZE` makes are allowed; anything else
this version does not make is not.

The store holds at most 500 website users (and as many records for users in the config file),
20 recovery codes and 10 known devices per user. A change past that is refused (the Users page
says "The user store is full", with 409 for the user count and 500 otherwise) and nothing
changes.

**Changes from the command line.** `scripts/users.js` may change the store while the server runs
(see "Managing users"); there is no lock file and nothing to stop first. The server looks for
such changes once a second and before each of its own writes, reads the store again, and signs
out every user who was made, deleted, or given another password, role or second factor there
(an audit line, `user-changed-elsewhere`, says who and what). A change of its own that runs
into one of those is given up, the users concerned are signed out first, and it is tried again,
so a request from a session that was just ended is refused. Each write holds the store for
milliseconds; a server that finds it held for more than a second answers that change with 500
"Another program is changing the user store; nothing was changed. Try again."

**When the store cannot be read again.** If what the server finds there cannot be read (a row it
cannot decrypt with the keys it has, a damaged row, a trigger or table put in by something
else), what it has in memory may be out of date: a user deleted there could still sign in. So
the server then turns signing in off (`/login` answers 503 "Signing in is not possible right
now. Try again later."), ends every session, logs an error line and writes
`user-store-unreadable` to the audit log. It tries again every second; once the store can be
read, signing in is back on by itself (`user-store-readable`). Fix what the error line says, or
restart the server with the right keys.

TOTP secrets are kept encrypted with the user store key, and recovery codes only as a keyed hash
(see "The user store"), so the database alone gives neither. Keep the data directory as private
as the config file anyway, and back it up (see "Backups"). A passkey's record (its public key,
name and counter) is in the store too; a public key cannot sign in.

**Two-step sign-in with an app code (TOTP).** On the account page, Set up two-step sign-in shows a QR code and the
same key as text, for any authenticator app (RFC 6238: HMAC-SHA1, 6 digits, 30 seconds). The key
is a new random 20-byte secret, and it is shown this once, to its owner: no later answer contains
it, it is never in a URL and never logged. It is only turned on once the first code from the app
is right; turning it on gives ten recovery codes, shown once too, with Copy and Download buttons
(they replace any recovery codes the user already had from a passkey). Each recovery code signs in
once instead of any other second step: the code from the app or a passkey. New recovery codes
replace all the old ones. The recovery codes belong to the second step as a whole: they are made
when the first way (app code or passkey) is turned on, and they are removed only when the last way
is turned off. Setting it up needs the password; new recovery codes and turning it off need the
password and a second step (a passkey, a code from the app or a recovery code) (see "Changes need
a recent sign in").

With a second step on, a right password no longer signs in by itself. `/login` answers 200 with
`{"ok": false, "secondFactor": true, "pending": "..."}` (and `methods`, the ways the user can answer, and
`passkey`, the options for the browser, when a passkey can be used here) and no cookie, and the sign in dialog asks
for the passkey, the code or, with "Use a recovery code", a recovery code. The code and the recovery code are posted to `/login/code`
with the `pending` token (a form, like `/login`); the passkey to `/login/passkey` (see "Passkeys"). The token is good for 5 minutes, for one sign in,
only from the address that gave the password, and for 5 wrong codes; then the dialog goes back to
the password. A wrong password gets the same answer as before, so nothing says whether a name has
a second factor before the password is right.

- A code is taken from the 30 seconds before, now and the 30 seconds after, so a phone clock that
  is a little off still works. Each code works once: a code (or an older one) that was used
  already is refused, also after a restart.
- Wrong codes count per user and address (per user and device for a known device), and per user
  from everywhere together. For a user and address, the first five are free; after that each one
  doubles the wait, up to an hour (answer 429 with `Retry-After` and the wait in words). For the
  user in all, 30 are free, then the same doubling wait, for every browser that is not a known
  device; a known device is only held back by it once the user has 200 wrong codes. They are
  remembered for a day after the last one, so the free tries do not come back after a short
  pause: someone who knows the password gets at most 40 guesses at the code from one address on
  the first day and 24 a day after that, and at most 65 on the first day from all their
  addresses together (then 24 a day). Someone with the password can so hold back the code step
  of the owner's new browsers, but not of a known device. A right password does not start the
  count again: it is only cleared by a right code. Wrong codes also count for the address in the
  same count as wrong passwords.
- This wait only holds back the code step, never the password step. A right password while it
  runs says so: with a wait shorter than the 5 minutes of a second step, `/login` gives the token
  with `codeWait` (seconds) and `notice`, which the dialog shows; with a longer one it answers 429
  "Too many wrong codes were entered for this account. Sign in again in N minutes." and no token.
  A code sent during the wait is answered 429 with the time; if the wait outlasts the token, the
  answer has `restart: true` and the dialog goes back to the password.
- A password change, turning the second factor off, and the other changes below end every second
  step of the user that is still open, also one started with the old password.

**Changes need a recent sign in.** Changing the password, setting up, turning on or off the second
factor, making new recovery codes and signing out other sessions need a sign in from the last 15
minutes. After that the page asks for the password again (`POST /api/account/reauth`) and then goes
on. That can be done at most 10 times an hour from one session and 20 times an hour for one user,
right and wrong passwords alike (a right one does not start the count again); past that the
answer is 429 with `Retry-After`. Some need more in the request itself, and the page asks for it
in a pop-up (the step-up dialog) when the button is pressed, not in boxes on the page:

- **Password change, new recovery codes, turning the app code off, adding and removing a
  passkey** (and every change on the Users page): the password (`password`) **and**, when a second
  step is on, a passkey (`passkey`), a current code from the app (`code`) or an unused recovery
  code (`recovery`). Neither is enough alone: the password alone is refused with 400 and
  `field: "code"`, a code alone with `field: "password"`. A wrong passkey is refused with 400 and
  `field: "passkey"`. A passkey is asked for with a challenge from `POST
  /api/account/passkeys/challenge` (409 when the user has no passkey that works at this address;
  30 a session and 60 a user an hour), and each challenge works once.
  A missing code is refused before the password is checked (no hash, no try counted); the code
  is only checked once the password is right, so a wrong password never uses up a code. A code
  counts like one at sign in: a wrong one counts in the same waits, and a code (and its 30
  seconds) works once, so a request cannot be replayed. A recovery code used here is used up and
  is an audit line, as at sign in. Users without two-step sign-in give the password only. The
  dialog has "Your password", and with two-step sign-in on asks for the passkey first (when the
  user has one that works at this address and the browser can use it), or "Code from your app", with
  "Use the code from your app instead" and "Use a recovery code instead" as the other ways; it keeps the keyboard focus inside, closes with Escape, gives the
  focus back to the button, and shows a wrong password or code inside it. When the sign in is
  older than 15 minutes, the password given there makes it recent again first.
- **Password change:** the current password is the step-up's password (`password`; `current`,
  the older name, is still read). It is for website users only. The new one needs at
  least 12 characters and at most 1024 bytes, must not be one of a built-in list of the most
  common passwords (any case), one character over and over, or the name with fewer than 8 other
  characters. Passwords in the config file are not checked: the server only has their hash, so
  pick them with the same care.
- **Set up the app code:** the password (`password`), in the same dialog, and a second step too
  when one is on already (a passkey, say); then the first code from the app, on the page, turns it
  on.

A password asked for while signed in counts in a wait of that session (five free, then doubling),
kept apart from every other count, so nobody outside can hold a signed-in user back by sending
wrong passwords for the name, nor push that wait out by filling the other counts.

A session can end while one of its changes is under way: a password change or sign out elsewhere,
or the user removed. Each change checks after every step that its session is still there, and
the store checks it again right before writing. If it is gone, the answer is 401, nothing is
changed, and no secret (a new key or recovery codes) is handed out. A password check that was
under way when the password changed does not sign in.

Changing the password, turning the app code on or off, adding a user's first passkey and removing
any passkey sign the account out everywhere else (adding a second passkey does not; the session
that made the change stays), drop any second step still open, and forget every
known device but the one that made the change. **Sign out other sessions**, under "Where you are
signed in" (`POST /api/account/sign-out-others`), does the same on its own.

**Known devices.** Under "Known devices" the page lists the browsers the account signed in from
(see "How the login works"). A device has no name the server knows, so each shows when it was
first and last used, and "this browser" for the current one. **Remove** forgets one (`POST
/api/account/devices/remove` with its `device` id from `GET /api/account`), and **Remove all
other devices** forgets every one but this browser (`POST /api/account/devices/remove-others`).
Removing a device also signs it out: every session that was signed in on it ends (the answer
says how many, `ended`), and removing this browser's own device signs this browser out. A
removed device is held back like any other browser until it signs in again. Removing takes effect
at once, also when writing the user store fails.

Setting up, turning on and off, new recovery codes, signing out other sessions and adding or
removing a passkey (the three steps `passkeys/begin`, `passkeys/finish` and `passkeys/remove`) can
each be done at most 5 times an hour from one session and 10 times an hour for one user, wrong
passwords and codes included; past that the answer is 429 with `Retry-After`. Renaming a passkey is
not counted.

A change is written to the user store first and only then made: when the write fails (a full
disk, a full user store, or the store held by `scripts/users.js` for longer than a second, see
"Changes from the command line"), the answer is 500 and says which ("Another program is changing
the user store; nothing was changed. Try again." for the last), nothing has changed, and nobody
was signed out.

**The account API.** `GET /api/account` says who is signed in, and never holds a secret. The
changes are `POST /api/account/reauth`, `/password`, `/totp/setup`, `/totp/enable`,
`/totp/disable`, `/recovery-codes`, `/sign-out-others`, `/devices/remove`,
`/devices/remove-others`, `/passkeys/challenge`, `/passkeys/begin`, `/passkeys/finish`,
`/passkeys/rename` and `/passkeys/remove`. `GET /api/account` also says whether passkeys are
available here (`passkeys.available`, with `reason: "no-address"` when `site.url` is not set), and
lists them (`passkeys.list`: `id`, `name`, `created`, `lastUsed`, `synced`, and `here`, false for a
passkey made for another address). Ids are short references, never the credential id or key. They
only take JSON (`Content-Type: application/json`, at most 16 KiB, as a new passkey's answer is
several kilobytes), with the header `X-Rettui-Request: 1`, from the page itself (`Sec-Fetch-Site:
same-origin`, or `Origin` naming the host, and nothing else: an `Origin` with a user name or a
path is refused); a form on another site can send none of these.
Without a session the answer is 401. All answers carry `Cache-Control: no-store`.

**Audit log.** `audit.log` in `DATA_DIR` gets one JSON line per security event, appended, mode
0600: `password-changed` (`with`), `totp-enabled`, `totp-disabled` (`with`: `password`,
`password+code` or `password+recovery`),
`recovery-code-used` (with how many are `left`), `recovery-codes-regenerated` (`with`),
`sessions-ended` (how many were `ended`), `device-added` (a sign in from a new browser),
`device-removed` and `devices-removed` (how many were `removed`, and how many sessions that
ended, `ended`). Turning on a first second factor (the app code, or a first passkey, with no
other second factor on) adds `second-factor-first` as well (`role`, `method`: `totp` or
`passkey`, and `nodeChangesFrom`: when the wait before node changes ends, see "Managing nodes").
Passkeys add `passkey-added` (`passkey`: its name, `first`: whether it is the
user's first second step), `passkey-renamed` (`from`, `to`), `passkey-removed` (`passkey`, `with`,
`ended`, `secondFactorOff`) and `passkey-counter-error` (`passkey`: a passkey answered right but
its counter did not go up, see "Passkeys"). A passkey is named by its name only: no credential id
or key is ever in a line. Changes on the Users page add `user-created` (`role`, and `password`:
`generated` or `typed`), `user-role-changed` (`from`, `to`), `user-deleted` (`role`),
`user-password-reset` (`password`) and `user-second-factor-reset` (with `passkeys`: how many
passkeys it removed); each of those has the admin
who made it (`actor`), the `user` it was made to, how many of their sessions `ended`, and how
the admin confirmed it (`with`). A change made with `scripts/users.js` is
`user-changed-elsewhere` (`what`: `created`, `deleted`, `password`, `role` or `second-factor`),
written by the server when it notices it. The server also writes `user-store-imported` when it
imports `users.json` (with `again: true` when a user store had been made in the data directory
before, see "From users.json"), `key-added` for each user store key version it sees for the
first time, and `user-store-unreadable` (`sessionsEnded`) and `user-store-readable` when the
store cannot be read again and when it can (see "When the store cannot be read again").
`user-role-changed` has the role the user had right before the
change, also when another change came in between. A try on the Users page to reset the password
or the two-step sign-in of an **admin** is refused and written as `admin-reset-refused`, with the
`actor`, the `target` admin and `what` they tried to reset (`password` or `second-factor`); a try
to give another admin a lower role is refused and written as `admin-demote-refused`, and a try to
delete another admin as `admin-delete-refused`, both with the `actor` and the `target` admin; see
"Managing users". Each line has the time, the user and the address. No password, secret, code or
device id is ever in it. Changes asked of a node on the Manage page add `manage-settings`,
`manage-restart`, `manage-rollback` and `manage-reticulum`, and the website's confirm of a Reticulum
change adds `manage-confirm` (see "Managing nodes"). `device-added` is only written for a user's first new browser in 24
hours, or when the new browser pushes out a known device older than that (`pushedOut`: how
many); the other new browsers are summed up in `failures.log`, so that an account signing in from
new browsers over and over cannot push the other events out of `audit.log`.

Wrong passwords and codes go to `failures.log` instead, so that no amount of them can push a
security event out of `audit.log`. They are summed up: one line per name and kind
(`password-failures`, `second-factor-failures`, and `device-added` for the new browsers above,
counted in `failures`) per 15 minutes, with how many `failures`, from
how many `addresses` (`100+` past a hundred), the `lastAddress`, and when the first and last were
(`from`, `to`). Every name gets its lines, known or not. A summary is written once its 15 minutes
are over, and all of them when the server stops. At most 10000 are summed up at once; past that
the oldest is written early.

Both are bounded: a line that would take one past 5 MiB first moves it to `.1` (and `.1` to `.2`);
three files of each are kept, the oldest is dropped. So copy `audit.log` off the server as it
grows (a log shipper, or a timer that copies it to another machine): a long enough run of events
still pushes old lines out, and whoever takes over the server can change the copy that stays on it.

## Passkeys

A passkey is a second step after the password. The user's phone, computer or security key confirms
it is them, with a fingerprint, face or PIN, and there is nothing to type. It sits next to the app
code (TOTP), not in place of the password: **passkey-only sign-in is not offered yet**. Users can
have an app code, passkeys, or both.

**What you need.** Users (see "Logins") and the site's public address:

- Set `site.url` in the config file, or `SITE_URL` without one, to the https address people use,
  like `https://status.example.org` (no path). For trying it out on your own machine,
  `http://localhost` (with or without a port) works too.
- Without it the Account page says "Passkeys need this site's https address in the config file
  (site.url, or SITE_URL)." and the server prints `passkeys: off` at start when it has users,
  with the reason (no address set, or one passkeys cannot use). The password and the app code are
  not affected.
- The address must have a host name. An IP address cannot be used for passkeys: `site.url` takes
  one (for the feed and the page previews), but passkeys stay off, and the start says "the site
  address (site.url, or SITE_URL) is an IP address; passkeys need a host name".
- **A passkey is tied to the host name** in that address (`status.example.org` above), and only
  works at the exact address it was made for. **Changing `site.url` later stops the passkeys made
  before working**: they stay in the list, marked "Not usable at this address.", and can still be
  removed. Users with an app code or recovery codes sign in with those, and an admin can reset the
  rest (see "Managing users"). Decide the address before people add passkeys.

In Docker, put it in `compose.yaml` and restart:

    environment:
      SITE_URL: "https://status.example.org"

(or `site.url` in the config file, if you use `CONFIG_FILE`). Behind a reverse proxy this is the
address the proxy serves, not `http://website:8080`.

**Adding one.** On the Account page, "Passkeys", give it a name if you like (up to 64 characters,
such as "Work laptop", without control, bidirectional or zero-width characters or more than three
accents in a row on one letter; the default is "Passkey 1", "Passkey 2" and so on) and press "Add a
passkey". A pop-up asks for the password, and for a second step when the user has one already.
Then the device asks the user to make the passkey. A user can have 10. The list shows each
passkey's name, when it was added and last used, and whether it is synced or device-bound. Each can
be renamed or removed. A name in the user store that these rules refuse (one changed by hand, say)
is shown as "Passkey N", by its place in the list, and the passkey keeps working.

- The first second step of a user (the first passkey, or the app code) gives ten recovery codes,
  shown once, and signs every other session out. A second passkey changes neither.
- Removing a passkey asks for the password and a second step, and signs every other session out.
- The Account page says when the browser cannot make passkeys. Users can still rename and remove
  the ones they have.

**Signing in.** The password comes first, as always. Then the dialog offers, in this order:

1. **Use your passkey**, a button. Pressing it makes the browser ask for the passkey. It does not
   start by itself, because some browsers (Safari) only show the prompt after a tap or click.
2. **Use the code from the app**, when the app code is on.
3. **Use a recovery code**, while any are left.

Only passkeys made at the site's current address are offered. A user who has passkeys but none that
work here still gets the second step, with the app code or a recovery code, and a note that the
passkey does not work at this address. A passkey that fails counts exactly as a wrong code: the
same waits and limits, and it is summed up in `failures.log` as
`second-factor-failures` (see "Two-step sign-in with an app code (TOTP)"). The same choice is made
when a change on the Account page or the Users page asks for a second step (the dialog asks for the
passkey first).

**Synced and device-bound.** Some passkeys are copied by the user's password manager or phone
account to their other devices ("synced"); others stay on one device or security key
("device-bound"). The Account page says which, going by what the device reported to the server. A
device-bound passkey is gone if the device is lost or reset. Recovery codes cover both, so tell
users to keep them.

**The counter and the clone warning.** A device-bound passkey counts its uses. When a sign in
answers with a signature that is right, but a counter that did not go up, the sign in is refused
and `passkey-counter-error` is written to `audit.log` (with the passkey's name). It can mean the
passkey was copied. Synced passkeys always send 0, which is accepted. The sign in dialog says that
passkey did not work and offers the other ways.

**When the last second step is removed.** Removing the user's last passkey (with no app code on),
or turning off the app code with no passkey left, turns two-step sign-in off: the recovery codes
are removed and the password alone signs in. The dialog says so before it goes ahead. While one
way is left, the recovery codes stay.

**Admin reset.** Reset two-step sign-in on the Users page (or `scripts/users.js reset-2fa NAME`,
the only way for an admin's) removes the app code, every passkey and the recovery codes, and forgets the known devices (see
"Managing users"). The audit line has how many `passkeys` it removed.

**Browsers.** A page can use passkeys only in a secure context: over https, or on `localhost`. Use
a current browser. Where the browser cannot use passkeys, the page says so, and the sign in
offers the app code and recovery codes.

**Going back to an older version.** An older version of this website knows nothing about passkeys.
So that it can never let a user whose only second step is a passkey sign in with the password
alone, the first passkey anyone adds raises the version of `users.db` (schema version 2), and the
version before passkeys then refuses to start with it ("made by a newer version"). A store where
nobody has added a passkey stays at version 1, and an older version reads it as before. To go back
after passkeys were used, remove every passkey (on the Account page, or with `reset-2fa` for each
user who has one, or the Reset two-step button on the Users page): when the last passkey anywhere
goes, the version goes back to 1 and the older version opens the store again. Give users who had
only a passkey the app code first, or tell them to set up two-step sign-in again afterwards: until
then their password alone signs them in.

**The library.** WebAuthn is checked by `@simplewebauthn/server`, the only package added for it.
Only `lib/passkeys.js` uses it, after it has checked the size and shape of everything the browser
sent.

- It is pinned to an exact version in `package.json` (no `^` or `~`), and `package-lock.json` is
  committed. The Docker image installs with `npm ci --omit=dev --ignore-scripts`, so no install
  script of it or of anything it brings runs. Run the same when you install outside Docker.
- Only attestation `none` is accepted (and `packed` signed by the new key itself, with no
  certificate). A passkey that comes with a certificate is refused: "This security key sent a
  certificate, which this site does not accept. Try another passkey." The library's certificate
  code never runs.
- There is no metadata service, and passkeys cause no request to any other server.
- To check that the downloaded packages are the ones the registry signed, after `npm ci`:

      npm audit signatures

The algorithms are ES256 (a P-256 key, a point on the curve), EdDSA (an Ed25519 key, not one of
the points of small order) and RS256 (an RSA key of at least 2048 bits, with the exponent 65537);
a key that is not what its algorithm says is refused when the passkey is added. The
device must verify the user (a PIN or biometrics). A passkey that another user has added already is
refused like one that could not be checked, so that nobody can find out which passkeys others
have; `failures.log` notes it as `passkey-id-taken`. The pages send
`Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)`, so a
page of another site cannot use passkeys for this one, even in a frame.

## Managing users

Admins (role `admin`) manage users on the **Users** page, `/users`. The Account page shows a
"Manage users" link to admins only. For everyone else (signed out, `manage`, `viewer`, or an
admin who still has to change a password an admin set) `/users` answers 404 and `/api/users`
401 or 403: the server decides, not the page.

**What the page shows.** Every user: name, role, where they come from (config file or website),
what two-step sign-in is made of ("Off", or "On" with "app code" and the number of passkeys, like "On:
app code, 2 passkeys"), how many known devices, last sign in and when they were made. No
password, hash, secret, passkey id or device id is ever sent. On a phone the table becomes one card per user.

**What an admin can do.**

- **Add a user** (website users only): a name (1 to 32 letters, digits, `.`, `-`, `_`), a role
  (`admin`, `manage` or `viewer`), and a first password. Either the admin types one (12+
  characters, the same rules as a password change), or the page makes a one-time password (20
  random letters and digits) and shows it once, with a Copy button: it is never shown again, not
  stored anywhere but as a hash, and not logged. Either way the new user must choose their own
  password when they first sign in.
- **Change the role** of a website user: anyone may be made an admin, but another admin is not
  demoted here (see below). An admin may give themselves another role.
- **Reset the password** of a website user: a one-time or typed password, as above, which they
  must change at their next sign in. An admin changes their own password on the Account page.
- **Reset two-step sign-in**, for someone who lost their phone or security key: it turns the app
  code off, removes every passkey and the recovery codes, and forgets every known device. The
  dialog names what will go ("app code, 2 passkeys, recovery codes and known devices"). This works for users in the config file too.
  An admin turns their own off on the Account page.
- **Delete** a website user who is not an admin (see below). An admin may delete themselves.

**Admins are reset, demoted and deleted on the server only.** The password and the two-step
sign-in of an admin (another admin, or one from the config file) cannot be reset on the Users
page: an admin who could do that could sign in as the other admin. For the same reason another
admin cannot be given a lower role there either (else: demote them, reset them, make them an
admin again), and cannot be deleted there, so that one admin cannot lock another out. The page
does not offer those actions on another admin's row, and says where they are done. The API
answers 403 and writes a line to `audit.log`, with who tried:

- a reset: "Admin accounts can only be reset from the command line on the server
  (scripts/users.js reset-password or reset-2fa).", event `admin-reset-refused`;
- a demotion: "Admins can only be demoted from the command line on the server (scripts/users.js
  set-role).", event `admin-demote-refused`;
- a deletion: "Admins can only be deleted from the command line on the server (scripts/users.js
  delete).", event `admin-delete-refused`.

This holds also when the user is made an admin while the request is under way: the store checks
the role again, on the record as it is then, right before it writes. Someone with access to the
server does these with `node scripts/users.js reset-password <name>`,
`node scripts/users.js reset-2fa <name>`, `node scripts/users.js set-role <name> <role>` or
`node scripts/users.js delete <name>` (see "The command line" below). An admin may still give
themselves another role, or delete themselves, while another admin exists (see "The last admin").
Give the admin role only to people you trust with every account.

Every way of writing the page's address (`/users.html`, `/users.html/`, `/%75sers.html`,
`/users%2ehtml`, other cases) goes through the same check as `/users`, and every way of writing
`/account.html` is the account page.

Each change to a user signs that user out everywhere, ends their open second steps and forgets
their known devices. Destructive changes ask in a dialog first, saying what will happen.

**Users in the config file** are read-only here, marked "Managed by config": their name,
password and role are changed in the config file. Only their second factor can be reset, and
only if they are not an admin.

**The last admin.** The last admin (counting the config file's admins too) can never be deleted
or given another role, also not by themselves. An admin may give themselves another role, or
delete themselves, only while another admin exists; they are then signed out at once.

**Safeguards.** Every change needs, all at once: an admin's session; a sign in from the last 15
minutes; while any node has a `manage_url` (see "Managing nodes"), the admin's two-step sign-in
turned on (else the answer is 403 with `code: "second-factor-required"` and the page says to turn it
on first: otherwise an admin's password alone would be enough to make a `manage` user, set up a
second factor for it, and change nodes through it), and not inside the 24-hour wait after their own
first second factor (else 403 with `code: "second-factor-new"`, asked again after the password; see
"The wait after a first second factor" under "Managing nodes"); the admin's password in the request itself, and with their two-step sign-in on their
passkey, a current code from their app or a recovery code as well, asked for in the step-up dialog (see
"Changes need a recent sign in"); the request header, same origin and JSON,
as for the account API (`POST /api/users/create`, `/role`, `/delete`, `/reset-password`,
`/reset-second-factor`, at most 16 KiB). Each admin may make 30 changes an hour, wrong passwords
and codes included (then 429 with `Retry-After`); a request that is refused before any password
is asked (an unknown user, a bad name) does not count, except a reset of an admin's password or
two-step sign-in, or another admin's demotion or deletion, which is refused with 403 before any password is
asked and does count, so that refusals cannot fill `audit.log`. Neither does one answered 503 because
too many passwords were being checked at once (the admin's own requests in parallel, say). After every step the server checks that
the admin's session is still there and still an admin's, and the store checks it again right
before it writes: an admin signed out or demoted meanwhile gets 401 and nothing changes. Each
change is an audit line with the admin and the user (see "Audit log").

**First sign in with a password an admin set.** The sign in works, and the answer says
`mustChangePassword: true`; the header sends the user to the Account page, which shows only the
password change. Until they choose a new password, the session can only change the password and
sign out: the status page shows them what a visitor sees, and every other account or users change
answers 403.

**The first admin.** There is no "first user becomes admin". With no admin anywhere, the Users
page does not exist. Make one in either way:

- give a user in the config file `role: admin` and restart the server, or
- run `node scripts/users.js create NAME --role admin` (it asks for the password twice without
  showing it, or reads it from stdin). It needs the user store key first (see "The user store
  key"). The server may be running: it picks the new user up within a second. But the server
  turns sign-in on only when it starts with users, so if it was started without any (or without
  a key), the command says "restart the website to turn on sign-in": restart it once. In Docker:
  `docker compose exec website node scripts/users.js create NAME --role admin`. That runs in the
  running container, as the image's `node` user like the server, with its data volume and its
  key. With the site stopped, `docker compose run --rm website node scripts/users.js ...` does
  the same.

**Run as root** (outside Docker, say), the command first becomes
the owner of the data directory (the server's user, with that user's groups), before it opens
anything, the key file included, and says so: the files it makes are then that user's, and
nothing that user can put in the data directory (a link in place of `users.db-wal`, say) can make
root write to or take over a file elsewhere. So **the key file must be readable by the owner of
the data directory** (directly or through one of their groups), as it is for the server; if it
is not, the command says so and does nothing. A backup is written as that user too, into a
folder they can write to. It works on the data directory by its real path (links resolved), and
refuses, changing nothing, when another user could change the way there meanwhile:

- a folder on the way belongs to a user other than root and the owner of the data directory, or
  others can write to it (unless it has the sticky bit and is root's, as `/tmp` is);
- the path goes through a link that is not root's, or lies in a folder that is not root's;
- the data directory does not exist yet, and others can write where it would be made;
- the data directory is root's and others can write to it (unless it has the sticky bit).

Only when root owns the data directory does the command stay root, and then it warns that the
new `users.db` is root's and a server running as another user cannot open it.

**The command line, `scripts/users.js`.** It works on the user store with the same rules as the
website (names, roles, password rules, the last admin), and needs the same key as the server
(`USERS_KEY_FILE` or `USERS_KEY`). It may run while the server runs: each change is one short
transaction, the password is hashed (with the pepper of the current key) before it starts, and a
running server picks the change up within a second and signs that user out. If the server is
writing at that moment, the command waits up to 10 seconds; after that it says "Another program
is changing the user store; nothing was changed. Try again." A store that cannot be read is left
as it is and nothing is done. The command makes `users.db` only for `create`, or to import a
`users.json`: any other command in a data directory without a store says so and makes nothing
(`list` says "No users"), so a mistyped `--data-dir` does not leave an empty store behind. A
`users.db` it made is never removed again, since a server starting at that moment may already
use it.

The command only uses key versions the server has recorded in the store, which it does when it
starts: a version added to the key file is used once the server was restarted with it. Until
then the command uses the newest version the server has, and says that the new one is not in use
yet, so the running server can always read what the command writes. (In a new store, before the
server ever started with a key, the command records its keys itself.)

    node scripts/users.js [--data-dir DIR] [--config FILE] COMMAND
      list                                  # role and two-step sign-in: app code, passkeys
      create NAME --role ROLE [--generate] [--must-change]
      set-role NAME ROLE [--force]
      reset-password NAME [--generate] [--must-change]
      reset-2fa NAME                        # app code, passkeys, recovery codes, known devices
      delete NAME [--force]
      backup FILE
      check
      rekey
      retire-users-json [--delete]
      gen-key [--version N]

`--data-dir` defaults to `DATA_DIR` (else `./data`), `--config` to `CONFIG_FILE`. With the config
file its admins count for the last-admin rule, its names cannot be taken, and `reset-2fa` works
for its users; without it, a note says so. `--generate` makes a one-time password, printed once,
that must be changed at the next sign in (`--must-change` asks the same of a typed one). A
password is never taken as an argument. `--force` lets the last admin be deleted or demoted, for
recovery only. `backup`, `check`, `rekey`, `retire-users-json` and `gen-key` are described in
"The user store".
`--server-stopped`, which older versions needed, is still accepted and ignored, with a note. An
unknown option or command is not repeated in the error, since a mistyped line may hold a
password.

**Recovery.**

- *Lost the only admin password, or the admin left:* `scripts/users.js reset-password NAME
  --generate` for a website admin, or `create NEWNAME --role admin`; or give a config user
  `role: admin` and restart the server.
- *An admin lost their phone or security key:* `scripts/users.js reset-2fa NAME` on the server
  (add `--config` for a user in the config file); the Users page does not reset an admin. It says what went, for example "their app code, 2 passkeys, recovery codes
  and known devices are gone". Recovery codes work too, if they still have them.
- *The user store key is lost:* see "Backups".
- *The key, or a copy of the data, may have been seen by someone else:* see "What the key does
  not protect".

**Moving users out of the config file.** Users in the config file never get the pepper (see "The
user store"); move them, admins first, to give it to them. Create each user in the store first
(on the Users page or with `scripts/users.js`), with a name that is not in the config file, or
with the same name in this order: remove them from `users:` in the config file, restart, then
create them in the store (on the page or with the command line). While a name is in both, the
config file wins: the server warns at start and the store user cannot sign in. Make sure an
admin is left (another one in the store, or the user you are moving) before you take an admin
out of the config file. A config user's two-step sign-in and devices are kept in the store apart
from the website users and are **not** moved: a store user made with the same name starts
without two-step sign-in and without known devices, and must set it up again on the Account
page. The old record stays, unused (the command line mentions it), and would be used again only
if the name went back into the config file; reset it there first (`reset-2fa` with `--config`)
if you want it gone.

## Managing nodes

Users with the role `manage` or `admin` can change a few settings of a rettui node, a few of its
Reticulum settings, and restart its Reticulum, on the **Manage** page, `/manage`. The Account page shows a "Manage nodes" link to them.
For everyone else (signed out, `viewer`, or someone who still has to change a password an admin
set) `/manage` answers 404 and `/api/manage` 401 or 403, and every way of writing the page's address
(`/manage.html`, `/manage.html/`, `/%6Danage.html`, other cases) goes through the same check.

This works only with nodes started as `rettui node` with a management listener (see below). The
node decides what can be changed: the page shows the settings it lists, and nothing else. Keys,
identities, adding or removing interfaces, programs the node runs and any other Reticulum setting
are not among them.

**What the page shows.** A list to pick the node; then, for that node:

- a status line: the rettui version, whether Reticulum is running and how many interfaces are
  online, and whether the node's clock agrees with the website's. From one minute off it says
  "This node's clock is N minutes off from the website's, so signed requests can't be trusted; fix
  the node's time." From five minutes off the node refuses every request with the same words.
- the node's Reticulum configuration, read only: one table per section (for example
  `interfaces / Hilltop TCP`) with each key and its value. The node decides what is shown; keys it
  holds back read "set (hidden)" or "not set". The website applies the same list itself: only
  type, enabled, mode, announce_cap, bitrate, ingress_control, enable_transport, share_instance,
  listen and target host and port, reachable_on and discoverable show a value, and an interface
  that runs a program (a pipe, or a command key) shows only its type and enabled. A note says when
  the node uses a shared Reticulum instance (the file shown is then the node's own; the live
  settings may be another process's). There is nothing to edit. The website keeps at most 128
  sections of 64 keys, with texts cut at 256 characters, and says "Part of the config is not
  shown." when anything was cut. An older node that sends no Reticulum config gets a line saying so.
- **Change the Reticulum configuration** (see "Reticulum changes on probation" below): for the
  sections the node offers, `enable_transport` under `[reticulum]`, and per interface `enabled`,
  `mode`, `announce_cap`, `bitrate` and `ingress_control`, with their current values. **Apply and
  test** sends only what you changed. A status line says how the change goes: restarting, on
  probation until a time, rolling back, kept, or rolled back with the node's reason.
- the settings form, grouped, with the help text of each setting and its current value. **Save
  changes** sends only the settings you changed. If someone changed the settings meanwhile (in
  the terminal, or another user), the node refuses, the page loads the form again and says so.
- services the website may only turn off (propagation node, node, hub, Git host and its pages):
  a **Turn off** button, greyed out while the service is off, with "Turn on in the terminal on
  the node". The website can never turn a service on.
- **Restart Reticulum**: the node restarts its network (on a shared `rnsd` it only reconnects).
  The page then asks the node every 3 seconds, for up to 2 minutes, whether every interface that
  was online is online again, and says how it went. The node allows one restart every 5 minutes.
- the last settings change, with a **Roll back** button. A roll back sets the values back through
  the same rules, so it cannot turn a service back on; the node refuses one when a setting of it was
  changed again since.
- the node's own list of changes, newest first, with who made them, the old and new values and how
  it went; **Older entries** loads more.

Everything a node sends is shown as text. On a phone the list of changes becomes one card per
change, and every control can be reached with the keyboard.

**Set it up.**

1. Make a secret for each node, 32 to 256 printable characters without spaces, quotes or
   backslashes, in a file only the owner can read:

       openssl rand -hex 32 > secrets/hilltop.manage && chmod 600 secrets/hilltop.manage

2. Give the node the same file and a listen address on a private network (loopback, 10/8,
   172.16/12, 192.168/16, 100.64/10, fc00::/7 or fe80::/10; the node refuses a public address):

       rettui node --manage-listen 10.200.0.2:8750 --manage-secret-file /path/to/hilltop.manage ...

   In the rettui Docker image, set `MANAGE_LISTEN=10.200.0.2:8750` and
   `MANAGE_SECRET_FILE=/run/secrets/hilltop.manage` (they only work with the `node` command).

   Make the link between the website and the node a tunnel (WireGuard, Tailscale) or put a TLS
   proxy in front of the listener. The node speaks plain http: the signatures stop anyone on the
   way from changing a request or faking an answer, but not from reading it, and every answer holds
   the node's settings, its Reticulum interfaces and addresses and who changed what. A shared LAN
   is not private enough.

3. Add the listener to the node in the website's config file, and restart the website:

       nodes:
         - address: hilltop.example.org:4242
           name: Hilltop
           manage_url: http://10.200.0.2:8750
           manage_secret_file: secrets/hilltop.manage
           # manage_confirm_seconds: 300

4. Give the people who manage nodes the role `manage` (on the Users page), and have them turn on
   two-step sign-in on their Account page. They can change nodes 24 hours after that (see
   "Safeguards"). Admins need two-step sign-in on too, to change anything on the Users page.

The config keys, in the config file only (there are no variables for them):

- `manage_url`: the address of the node's listener, an origin only (`http://host:port`, no path,
  query or fragment). Plain `http` is allowed only for the private addresses the node itself
  listens on: loopback (`127/8`, `::1`, `localhost`), `10/8`, `172.16/12`, `192.168/16`,
  `100.64/10` (Tailscale), `fc00::/7` (WireGuard and Tailscale) and `fe80::/10`. A public address or
  any other host name needs `https`. `stats_url` keeps the narrower list (loopback and `10/8`,
  `172.16/12`, `192.168/16`).
- `manage_secret_file`: the file with the node's secret, relative to the config file. It must be
  readable and writable by its owner only: a file the group or others can read or write stops the
  server at start, with a message to `chmod 600` it (on Linux and macOS; Windows has no such modes). In Docker, give the
  file to the user the website runs as (`sudo chown 1000 secrets/hilltop.manage`). Each node
  needs its own secret: two nodes with the same one stop the server at start, and so does a secret
  that is also a stats token (of any node). `manage_url` without a secret file, or the reverse,
  stops it too.
- `manage_confirm_seconds`: 60 to 900, default 300. How long a node waits for the website to
  confirm a change of its Reticulum config, once Reticulum is back with it (see "Reticulum changes
  on probation"). Sent with each change.

The secret is read once at start and kept in memory only: it is never in `users.db`, a log line,
an error, an answer of the API or the page.

**Threat model, in plain words.** Every request to a node is signed with that node's secret, with
the time and a number used once, so nobody on the way can change it; the node signs its answer, so
nobody on the way can fake an "ok". The node refuses a request it has already seen since it
started, and one whose time is more than 5 minutes off its clock. A request held back on the way
can still arrive late, within those 5 minutes, and be carried out then, so keep the link between
the website and the node private. The listener is not part of Reticulum, so a broken network does
not lock you out. Anyone who holds a node's secret can change what the website can change on that
node; anyone who takes over the website server can do so on every node set up here. That is why
the list of settings is small, a service can only be turned off, and each node has its own secret
(different from its stats token too: the server does not start if one is the same). To take the
website's access away from a node, remove `--manage-listen` (or `MANAGE_LISTEN`) there and restart
it.

**Firewall the manage port.** Only the website server may be able to connect to the node's manage
port: block it for everyone else, with a firewall on the node or a private network. Anyone who can
reach the port can lock the website out of that node, for as long as they keep sending it bad
requests. A reverse proxy in front of the listener is fine only if it lets in the website server
and nobody else, and passes the request path and query on exactly as they came: the node checks
the signature over them, so a proxy that rewrites them makes every request fail.

**Safeguards.** Looking needs a session with the role `manage` or `admin`, asked again on every
request. Each user may read each node 120 times an hour (the state and the list of changes,
polling during a restart included); then 429 with `Retry-After`. Every change needs, all at once:
the role; a sign in from the last 15 minutes (else the page asks for the password again); two-step
sign-in turned on for the account (without it the answer is 403 with `code:
"second-factor-required"`, and the page only shows), and on for at least 24 hours when it was the
first second factor (see below); the password and the passkey, a code from the app or a recovery
code in the request itself, asked for in the step-up dialog; and the request header, same origin
and JSON, at most 16 KiB (`POST /api/manage/settings`, `/restart`, `/rollback`, `/reticulum`). Each user may ask
30 changes an hour of all nodes together, wrong passwords and codes included; a change the node was
too busy for (503) does not count. Right before the node is asked, the server checks again that the
session is there and still has the role, and that no wait has started meanwhile: if not, the answer is
401 (or 403) and nothing is sent. The node limits changes too (10 a minute, one restart every 5
minutes).

**The wait after a first second factor.** A first second factor (the app code or a passkey, turned
on on the Account page while no other was on) is confirmed by the password alone. So for 24 hours
after it, its user can look at nodes but not change them (and an admin cannot change users while
nodes are managed): the answer is 403 with `code:
"second-factor-new"` and `nodeChangesFrom` (when the wait ends), and the page says until when. A
stolen password is then not enough to set up a factor and change a node at once, and the owner has
a day to notice the `second-factor-first` line in `audit.log`. A second factor added while another
is on (and so confirmed by it) starts no wait. A second factor set up again after an admin reset
it is a first one again, and waits. Users who had a second factor on before this version do not
wait. The waits are kept in `second-factor-holds.json` in `DATA_DIR` (mode
0600), apart from `users.db` so that older versions still read the user store, and a restart does
not end them, nor does setting the clock back (a wait is cut to at most 24 hours from now, never
dropped). A file that is there but cannot be read, or is of another version, is moved aside at
start to `second-factor-holds.json.unreadable-<time>` and said once; the waits then start empty. If
it cannot be moved, it is never written over, and the waits are kept in memory until the server
stops.

What the node refuses is said in fixed sentences (it changed elsewhere, it is busy, the clock is
off, it could not be reached, its answer was not signed). For a change, an answer without a valid
signature (the node does not sign a refusal of a request it saw before, nor its answer to one that
took over 5 seconds to arrive) means the outcome is not known: reload the node before trying again.
A node that restarted moments ago takes no request signed before it started (`before_start`): the
answer is 503 with `code: "before_start"` and `Retry-After`, from what the node says (at most 10
minutes), and until then a change is refused before the step-up, so trying again too soon uses up no
code. The code of the change that met it first is used, since the node is asked only after the
step-up. Only the node's words for a value it does not
accept, or a change it does not allow, are passed on, cut to 300 characters. When a node does not
answer in time the page says so, and nothing is taken as done: reload the page to see what the node
did.

**Reticulum changes on probation.** A change of the Reticulum config is made by the node in its
config file, one line per setting (the rest of the file stays as it is), and only when the node can
tell for sure which line it is: a section or key that is there twice, or in two spellings, is
refused with the node's reason, to be changed in the terminal. The node keeps the old file in its
config history, then restarts Reticulum. Once Reticulum is back with every interface that was
online and is still meant to be, the change is **on probation** for `manage_confirm_seconds`. In
that time the website's confirm job tries a TCP connection to the node's `address` from the config
file (the Reticulum port the status page checks), every 5 seconds; once that works, and the user who
made the change still has the role `manage` or `admin`, it confirms the change as that user, and
the node keeps it. If Reticulum does not come back within 90 seconds, or nothing confirms in time,
the node puts the old file back by itself and restarts Reticulum again. So a change that cuts the
website off from the node undoes itself.

- Only one change at a time: while one is pending the node refuses another change and a restart
  ("Another Reticulum change on this node is still being tested. Wait until it is kept or rolled
  back."). A node with a shared Reticulum instance takes no change.
- The confirm job lives in the website's memory. **When the website restarts during a probation,
  nothing confirms, and the node rolls the change back** at its deadline. The same when the node
  stops during a change: it puts the old file back before Reticulum starts again.
- The probe only shows that the probed port is up. A LoRa or other link the change broke is not
  checked; look at the interfaces on the status line.
- Turning an interface or transport on is offered only when the node allows it
  (`reticulum_enable_allowed` in its state); otherwise the page says it is only possible in the
  terminal, and the website refuses it too. When it is allowed, the dialog lists what the change
  opens (a server interface opens its listening port, transport relays for others) and **Apply and
  test** needs a box ticked; once applied, the node's notes say what it opened.
- The confirm job acts for the user who made the change only while that is still so: it gives up
  (and the node rolls back) when the user loses the role, signs in differently (a new password, a
  reset, two-step sign-in turned off, a password to change: `signin-changed`), or the session the
  change was made in ends (`session-ended`). A node that limits requests (429) is waited out for
  as long as it says, at most 5 minutes; the deadline is checked again right before the confirm.
- The node allows one Reticulum restart every 5 minutes, changes included (its automatic roll back
  aside).
- The page asks the website how the confirm job goes every 3 seconds while it runs
  (`GET /api/manage/confirm?host=`, which never asks the node; 1200 an hour per user), then reads the
  node once. The job asks the node's state every 5 seconds without using your 120 reads, stops
  sending 5 seconds before the deadline, and gives up 60 seconds after it, or 20 minutes in all.

**Audit.** Each change asked of a node is a line in `audit.log`: `manage-settings`,
`manage-restart`, `manage-rollback` or `manage-reticulum`, with the user (`actor`), the node
(`host`), the setting names (`keys`; for a Reticulum change `interfaces/<name>/<key>` or
`reticulum/<key>`), the node's change id (`id`, `null` when it refused), `result` (`ok`, or what went
wrong, like `stale_revision`, `not_allowed`, `pending`, `timeout` or `unsigned`), how the change was
confirmed (`with`) and the address; a roll back also has the id it rolled back (`of`). The end of
each confirm job is a `manage-confirm` line with the `actor`, `host`, `id` and `result`: `ok` (kept),
`not_pending` (the node ended it another way; `outcome` says how, like `rolled_back`),
`probe-failed`, `role-gone`, `signin-changed`, `session-ended`, `gave-up` or the code the node
refused the confirm with. The values are
never in it: the node keeps them, in its own list of changes, which the page shows.

## The user store

The users made on the website, and the second factor of every user, are kept in `users.db` in
`DATA_DIR`, a SQLite database (Node.js's built-in `node:sqlite`). The server and
`scripts/users.js` can both use it at the same time.

**What the key protects.** The user store has a key, which you make and keep apart from the data:

- **Passwords are peppered.** A password hash is made with the key mixed in (the "pepper"), so a
  stolen `users.db` alone is no use for guessing passwords: without the key, no guess can be
  checked. Each hash records which key version made it (`keyid` in the hash).
- **TOTP secrets are encrypted** (AES-256-GCM), each tied to its user, so the secrets of the
  authenticator apps cannot be read from the file, or moved to another user.
- **Recovery codes** are kept as a keyed hash (HMAC) of the code.

From the key three separate keys are derived, one for each of these. The key is never stored in
the database; only a short check value is, so that a wrong key is noticed at start.

Passwords that were in the store before it had a key (imported from `users.json`) have no pepper
yet. They keep working, and each is peppered the next time its user signs in. **Users in the
config file are never peppered**, because the server cannot rewrite that file: protect the config
file as before, and move admins into the store to give them the pepper (see "Moving users out of
the config file"). Their second factor, kept in the store, is encrypted like everyone's.

**What the key does not protect.**

- **The pepper protects reading, not writing.** Someone who can only read `users.db` learns
  nothing they can use. Someone who can **write** to it (or to the data directory) can put in a
  password hash or a user of their own and take over accounts, key or not. Keep the data
  directory writable by the server's user only.
- **`users.json` and old backups.** A `users.json` from an older version holds the second-factor
  secrets unencrypted and password hashes without a pepper, as they were at the import. It stays
  in the data directory until you retire it (see "From users.json"), and every backup of the data
  directory or volume made before that holds it too. Treat those backups as secret, and delete
  them when they are no longer needed.
- **Key and data seen together.** Whoever has the key and a copy of the data has everything the
  key protects, and changing the key (see "Changing the key") does not help against them: they
  already have the secrets. Then also reset every user's second factor (`reset-2fa`, after which
  they set up two-step sign-in again and get new recovery codes) and password (`reset-password
  NAME --generate`).

### The user store key

The key is needed as soon as there are users, in the config file or in the store: without it the
server does not start, and says to set `USERS_KEY_FILE` and that `node scripts/users.js gen-key`
makes one. A site without logins needs no key.

Give it in a file, `USERS_KEY_FILE` (a path), or inline in `USERS_KEY` (not both; the file is
safer). The file has one line per key version, `VERSION:KEY`:

    # The user store key. Keep it out of the data directory and its backups.
    1:KEY-OF-43-CHARACTERS-FROM-GEN-KEY

`VERSION` is a number from 1 to 65535, and `KEY` 32 random bytes in base64url (43 characters).
Entries can also be separated by commas (handy for `USERS_KEY`), and `#` starts a comment. At
most 16 entries, and the file at most 4 KiB. The highest version is the current one: new
passwords, TOTP secrets and recovery codes use it. The others are only read.

When you run `scripts/users.js` as root, it works as the owner of the data directory (see
"Managing users"), so the key file must be readable by that user (or one of their groups), like
it is for the server.

**Making one.** `node scripts/users.js gen-key` prints a new line, `1:...`; `--version N` gives
another version (for a new key, see "Changing the key"). It only prints; the store is not read.

    mkdir -p secrets
    (umask 077; node scripts/users.js gen-key > secrets/users.key)

Without Node.js on the host, use the image (`-T`, so that only the key line goes to the file):

    (umask 077; docker compose run --rm -T --no-deps website node scripts/users.js gen-key > secrets/users.key)

**In Docker**, give the file to the container as a secret, in `compose.yaml`:

    services:
      website:
        environment:
          USERS_KEY_FILE: /run/secrets/users_key
        secrets:
          - users_key
    secrets:
      users_key:
        file: ./secrets/users.key

Compose mounts the file as it is, with its owner and mode, at `/run/secrets/users_key`. The
server runs as uid 1000, so make the file that user's and readable by nobody else:

    sudo chown 1000 secrets/users.key
    sudo chmod 400 secrets/users.key

(If the container runs as another user, `user:` in `compose.yaml`, give the file to that uid.)

**Keep the key outside the data directory**, and so outside the data volume: whoever has a copy
of the data and the key has everything the key protects. The server and the command line warn at
start when `USERS_KEY_FILE` lies inside `DATA_DIR`, or can be read by other users.

**Losing the key** makes every TOTP secret and every peppered password in the store unusable;
nothing can bring them back. Keep a copy of the key file somewhere safe, apart from the backups
of the data (see "Backups").

### Backups

Back up the database and the key **separately**:

- **The database:** `node scripts/users.js backup FILE` writes a consistent copy of the store to
  `FILE`, a new file (it never writes over one, nor through a link), with mode 0600, while the
  server runs. It is made in a new private folder next to `FILE`, checked to be the very copy it
  made (yours, mode 0600), and then put in place, so a failure leaves nothing behind. A folder
  other users can write to is refused (unless it has the sticky bit, as `/tmp` has). Do not copy `users.db` itself while the server runs: the newest
  changes may still be in `users.db-wal`. Keep backups out of the repository and out of the
  image: write them to a folder of their own outside the repository, such as `~/backups`
  (`backups/`, `*.db`, `*.db-wal` and `*.db-shm` are in `.gitignore` and `.dockerignore` in case
  one ends up there anyway). In Docker, write it into the data volume and copy it out:

      mkdir -p ~/backups && chmod 700 ~/backups
      docker compose exec website node scripts/users.js backup /data/users-backup.db
      docker compose cp website:/data/users-backup.db ~/backups/users-$(date +%F).db
      docker compose exec website rm /data/users-backup.db

- **The key file**, kept somewhere else (a password manager, an offline copy).

To restore, stop the server, move `users.db`, `users.db-wal` and `users.db-shm` away, put the
backup in their place as `users.db` (owned by the server's user, mode 0600), and start with the
same key. **A backup without its key** loses everyone's TOTP secret and every peppered password:
the server does not start with the wrong key, and without one at all. To recover from that, make a
new key, move the old `users.db*` away, make a new admin with `scripts/users.js create`, and have
users made again, or start from a `users.json` (see "From users.json"). A `users.json` is the
store as it was at the import, long ago perhaps: it brings back users deleted since, and old
passwords and second factors. After any import of an old `users.json`, check the users
(`scripts/users.js list`), delete those that should be gone, and reset everyone's two-step
sign-in (`reset-2fa`) and password (`reset-password NAME --generate`).

`node scripts/users.js check` checks the database (SQLite's `quick_check`), that its schema is
exactly the one this version makes (no other tables or columns, no triggers or views), and the
key, and says what each key version still protects; run it after a restore, or now and then.

### Changing the key

Rotate the key when it may have been seen by someone else, or now and then:

1. Add a new line with the next version to the key file, keeping the old line:
   `(umask 077; node scripts/users.js gen-key --version 2 >> secrets/users.key)`.
2. Restart the server. It records version 2 in the store when it starts, and new passwords, TOTP
   secrets and recovery codes now use it. Until then `scripts/users.js` keeps using version 1,
   so that the running server can read what it writes, and `rekey` refuses: "Restart the
   website first".
3. Run `node scripts/users.js rekey` (in Docker: `docker compose exec website node
   scripts/users.js rekey`). It encrypts every TOTP secret again with the new key, and prints
   what each version still protects, for example "version 1: 3 password hashes (upgraded at next
   sign in), 12 recovery codes (replaced when used or regenerated), 0 TOTP secrets; still
   needed, keep it in the key file".
4. Remove the old line only when `node scripts/users.js check` says "version 1: unused; it can
   be removed from the key file". Password hashes move to the new key when their user signs in,
   and recovery codes when they are used or new ones are made, so this can take a while; a reset
   (`reset-password --generate`, or new recovery codes) moves them at once. Removing a version
   that is still needed makes the server stop at start with "the user store needs key version
   1; it is not in USERS_KEY_FILE": put the line back.

Rotating the key keeps a key that leaks later from opening what was in the store before, but it
does not help if the old key and a copy of the data were seen together: see "What the key does
not protect".

The store keeps a check value for each key version it uses, so that a wrong key is noticed. A
store that has users but no check value at all, or whose data uses a version without its check
value (something removed them), is refused at start, with the right key as with a wrong one:
restore it from a backup.

### Where to keep it

Keep `/data` on a **named local volume** (as `compose.yaml` does) or a local disk. The store uses
SQLite's write-ahead log, which needs shared memory between the server and the command line:
never put it on NFS, SMB or any volume shared between hosts, where it can be damaged. Run one
server per store.

The server makes `users.db` with mode 0600, and SQLite makes `users.db-wal` and `users.db-shm`
next to it with the same mode. Keep all three together: moving or copying `users.db` alone loses
recent changes. The server also writes `user-store.created` and keeps it: the time the first
store was made in this data directory, and a second line once a store here had users. That is
how a later import of `users.json` into a new store is noticed as a step back (see "From
users.json"). Moving `users.db*` away leaves it, as it should.

### From users.json

Older versions kept the users in `users.json`. At its first start (or the first
`scripts/users.js` command), this version imports `users.json` into a new `users.db`, once, in
one transaction: TOTP secrets are encrypted, recovery codes keyed, passwords stay unpeppered
until their next sign in. It needs the key if `users.json` has users. A `users.json` that
cannot be read (or is a link, or not a plain file) stops the start and is left as it is; nothing
is made. `users.json` itself is never changed or removed by the server, and is not read again: a
warning at start says when it was changed after the import. Fields this version does not keep
are dropped and named in a warning (names that do not look like field names are only counted).

**Retire it after the import.** `users.json` still holds the second-factor secrets unencrypted and
password hashes without a pepper. As long as it is in the data directory, every start warns
about it. Once the import worked (and you have a backup of the store), run `node scripts/users.js
retire-users-json`: it checks that `users.json` is the very file that was imported, and renames
it to `users.json.imported` with mode 0600 (it refuses a changed file or an existing
`users.json.imported`). Every start warns while `users.json.imported` is in the data directory
too: move it to offline storage, or delete it. `retire-users-json --delete` deletes instead of
renaming, after the same check: `users.json`, or `users.json.imported` once it was renamed.
Deleting does not wipe the disk blocks it was on, and backups of the data directory made before
then still hold it.

**Importing it again** brings the old snapshot back. Moving `users.db*` away and starting imports
`users.json` again into a new store: every user deleted since comes back, with the password and
second factor they had then. The server warns loudly when a store with users had been made in
the data directory before ("users.json is the snapshot of an older import"), and the audit line
has `again: true`. A first import after a start without users (users.json put in place later) is
not warned about. After that, check the users, delete those that should be gone, and reset every
password and two-step sign-in. A `users.json` with users that was never imported (put there after
the store was made) stops the start when neither the store nor the config file has users, since
the site would otherwise run without sign-in: move it away, or move `users.db*` away to import it.

**Going back to an older version** reads `users.json`, which is the store as it was at the import:
every change made since (new users, passwords, second factors) is lost there, and users deleted
since are back. Rename `users.json.imported` back to `users.json` for that, and reset passwords
and two-step sign-in afterwards as above. An older version
also does not know `users.db`, the key or the pepper.

`users.lock`, which older versions kept in `DATA_DIR`, is no longer used and can be removed, and
the 8 MiB limit on `users.json` applies only to the import now.

## Node logs

A node's Full details has a **Logs** tab with its recent log lines. It needs rettui started with `--stats-logs` (which adds a `/logs`
endpoint to its stats server), and the node's stats token (see "Exact peer counts"): without a token, or on an older
rettui, the tab is not offered. The page never reads logs by itself. Opening the tab asks once, and
the Refresh button asks again; there is no automatic refresh.

The address is made from the node's `stats_url`: with `https://host/stats.json` it is `https://host/logs`, and
with a path of its own, such as `https://stats.example/front`, it is `https://stats.example/front/logs`. A proxy in front
of the node must pass that on.

- **Who sees it.** Logs can hold addresses and other private things, so they are never public by
  omission: `require_login` has no say in them, and a list with or without sections (even `[]`) never
  exposes them. Only a logged-in visitor reads them, and only when they may see the node's `details`.
  To show a node's logs to everybody, set `public_logs: true` on that node, or at the top level for
  all nodes (a node's own value wins; default `false`). The server logs a warning at start for each
  node that has it. The details still apply: a node with `public_details: false`, or `details` locked,
  has no public logs. Without `public_logs` and without users there are no logs and `/api/logs/...`
  answers 404. A visitor who may not read the logs is not told which nodes serve them: the detail and
  combined answers leave out `logs` and `hasLogs` for them, and `/api/logs/...` checks access before it
  looks at the node (a 401 for a locked node, whether or not it has logs).
- **The request.** `GET /api/logs/<host:port>?lines=<1 to 500, default 200>&level=<error|warn|info|debug,
  default info>`. The website asks the node for `GET <origin of stats_url>/logs?lines=...&level=...`
  with the node's token in the `Authorization: Bearer` header (the same rule as for the stats: https, or
  http for private addresses). The token is never in a URL and never sent to the browser. A bad query is a
  400 (`level=trace` is refused: the node answers up to `debug`); an unknown host, a node without a token, and a node that answers 404 are a 404 ("this node does
  not serve logs (needs a newer rettui started with --stats-logs, and a stats token)"); no login is a 401; any other failure is a 502
  with a fixed sentence. Nothing the node says in an error is passed on.
- **Rate limit.** The answer to a question (node, lines and level) is kept for 5 seconds and shared by
  everybody who asks the same (a failure too), so the same question is one fetch. A new question costs
  the node a fetch, and is limited twice: each viewer (the login name, or the client address when nobody
  is logged in, which only happens with `public_logs`) may start one new question per node every 5
  seconds, and a node is asked once every 2 seconds across all viewers. Fetches that come sooner wait
  their turn (up to 4 in line); only past that, or for a viewer who asked too soon, is the answer a
  429 with `Retry-After`, which the tab shows as "Try again in N seconds". So one viewer who changes
  the question again and again gets 429 for themselves only. At most 200 answers and 1000 viewers are
  kept, they expire, and nothing is written to a file. Behind a reverse proxy that is not in
  `login.trusted_proxies`, visitors without a login share one address (see "Behind a reverse proxy").
- **What is kept of the answer.** Answers over 1 MiB are refused. At most 500 lines are kept (the newest,
  as the node lists them oldest first), and the answer says when older ones were left out. Each line
  is `{time, level, text}`: the text loses control, bidirectional and zero-width characters (a line
  break or tab becomes a space) and is cut to 1000 characters, the time is cut to 40, and the level is
  one of `error`, `warn`, `info`, `debug`, `trace` or `null`; a line that has no text is dropped.
- **The tab.** Level and Lines choices, a Refresh button, and a list in the code font. Each line
  shows its level in words (Error, Warning, Info, Debug) as well as in colour. The status text
  ("12 lines, oldest first, at level info and above", "Older lines were left out", or why it failed) is a
  live region. All text is set as text, never as HTML. For a proxy's combined view the tab has a Node
  choice: logs are shown for one node at a time, never added up.

## Propagation node and disk numbers

A node that runs an LXMF propagation node can add a `propagation` object to its stats, and any
node can add a `disk` object. Both are optional: an old node, a node with the propagation node
turned off (no `propagation` key, or `enabled` not true) or a node that has not measured its disk
yet just shows nothing for them. Each number inside is optional too; a missing or wrong one is
left out (shown as nothing) and never makes the rest of the stats unavailable.

- `propagation`: messages stored and their size (and the storage limit), peered nodes (alive,
  total, static, automatic, the peer limit, inbound links, whether auto-peering is on),
  messages received, served, sent to peers and received from peers, and the messages waiting to
  send to peers (`unhandledMessages`).
  Counters count since the node started, except messages offered to peers, which may include
  earlier runs. `unhandledMessages` is a sync backlog, not unprocessed mail: the stored messages a
  node still has to offer to its peer nodes, counted once for each peer (one message waiting for
  3 peers counts 3). It is high right after peering starts and falls as peers catch up. It can lag
  behind the real number.
  `unhandledDistinct` (rettui 2.1.0 and later; `null` from older nodes) counts those stored
  messages once each, so it never exceeds `storedMessages`: 20 messages that 20 peers wait for
  are 20 here and 400 in `unhandledMessages`. It is part of the storage numbers, so
  `require_login` takes it out together with `unhandledMessages`, and it is in `/api/status`,
  `/api/stats` and `/api/public/stats` (under `propagation`). For a group (nodes behind one
  proxy) the sums above are added up over the nodes, but `unhandledDistinct` is the largest value
  of one node (a lower bound), because nodes may wait for the same messages; `null` if no node
  sends it.
  The status page shows "Messages waiting for peers: N of M stored" when the node sends the
  distinct count, with "Total across peers: S" (the sum) as a second line in the details. For a
  node without it, and for a group, it shows "Waiting to send to peers (summed over peers)".
  The BACKLOG warning appears when the distinct count is larger than the stored messages (which
  cannot happen), or, with only the sum, when the sum is larger than the peered nodes times the
  stored messages. A large backlog on its own is normal and gives no warning. The warning does not
  look at per-peer sync failures: the website keeps only the counts of the peer rows, so
  `sync_failures`, `last_attempt_seconds_ago` and `next_attempt_in_seconds` are not part of it.
  The peer table does show each peer's `last_failure`.
- `disk`: the size of the node's data (public on the node) and, only in the answer to a request
  with a token, free and total space of the file system it is on (see "What is public").

`/api/status` carries them in `stats.data.propagation` and `stats.data.disk`.

On the status page these numbers are under "More" (message store, disk) and in the Storage and
Disk sections of Full details. The row itself says nothing unless: the disk is 75% used or
more (90% or more reads "almost full"), fewer than half of the peered nodes are alive, or the
waiting-to-send backlog is more than stored messages times peered nodes (it cannot be, so the
numbers are wrong or stuck; the row has no history to judge a trend). Any smaller backlog is
shown only as a fact under "More", not as a warning.

For a proxy group, `group.data.propagation` adds up stored messages and bytes, peered nodes,
message counters and the waiting-to-send backlog over the reporting nodes that have them (`nodes` says
how many), and `group.data.disk` has the summed data size and `lowestFree`: the node whose disk
has the smallest free share. Free space is not added up, because each node has its own disk.
Members that are down or stale are left out, as for the other numbers.

**History.** The numbers are sampled with the other stats and kept in the same
`stats-history.json`, in a separate `extra` list per node, so that the main `samples` keep the
layout older versions read (an older version ignores `extra`, and a file without it loads as
before). Each entry is checked when loaded and bad ones are dropped, like the others. The
detail answer has `series.propagation` (`storedMessages`, `storedBytes`, `peersAlive`,
`peersTotal`, `sentPerMinute`, `receivedPerMinute`) and `series.disk` (`dataBytes`,
`fsFreeBytes`), each `null` when the node never sent them. The two message counters are
cumulative, so they are turned into messages per minute the same way as the byte counters: a
counter or uptime that goes down is a restart and a long gap is missing data, both left as gaps.
In the combined view of a proxy the stored messages and bytes, peered nodes and message flow
are summed, only nodes that have these numbers count, and a point is summed only when all of
them are in it; for the disk the data size is summed and the free space is that of the node with
the least. The Storage section draws stored messages (the size is in the tooltip and the facts), peered
nodes (alive and total) and, on a propagation node, message flow to and from peers. The Disk
section shows the disk level and data size as facts, and draws the free space graph only when
`public_disk_figures` is on.

**Peers table.** With a stats token (see "Exact peer counts") a node also lists the propagation
nodes it peers with (`propagation_peers`: address, name, state, how long ago it was heard or
synced, counters). In the node's Full details, the Storage tab then has a "Propagation peers"
section: a line such as "12 peers: 9 alive, 3 static, 2 never synced", a "Show only peers with a
problem" switch, and a table (a stack of cards on a phone) with Name, Type (static or auto, and
depth), State (in words: "Alive, idle", "Not alive, connecting"), Last sync, Offered, Waiting
(messages not yet offered to that peer), Failures, Last failure (why the last try failed, in
words such as "Bad peering key" or "Timed out", or "-") and Next attempt. A peer that never synced or
whose last tries failed is marked in words ("Never synced", "Failing: 3 tries"), not by colour.
A peer without a name shows the first 8 characters of its address; the whole address is the
tooltip. The times are as of the last stats check, not live.

- **Who sees it.** Only the node's own Full details, and only when the node has a stats token.
  The rows follow the `peers` section of `require_login`, like the peered nodes count: a visitor
  without a login gets no rows (and no table); `details` locked or
  `public_details: false` hide the whole view as before. A proxy's combined view shows no
  per-peer rows, and neither do `/api/status` and `/api/public/stats`: the rows are in
  `/api/stats?host=...` (node view) as `stats.peerRows`, next to `stats.peerSummary`
  (`{listed, alive, static, unhandled, truncated}`).
- **Kept.** The current rows only, in memory: they are replaced at every fetch, dropped when a
  fetch has no list, and never written to `stats-history.json` or any other file.
- **Caps.** At most 256 entries of the node's answer are looked at; a row needs a valid 32
  character lower case hex address (a repeated address counts once, bad rows are dropped); at
  most 64 rows are kept, in this order: static peers first, then the most recently synced
  (never synced last), then by name, then by address. The summary line says "64 of 90 peers
  shown" when rows were left out. A name loses control, bidirectional and zero-width characters
  and is cut to 64 characters; a state is a short lower case word or `null`; numbers are whole,
  non-negative and at most 10^12; a field of the wrong type becomes `null`.
- **Versions.** The rows need the stats token. The sync columns (Last sync, Failures, Next
  attempt, and the "never synced" count) need rettui 2.1.0 or later; a node on an older version
  sends rows without them, and the table then has fewer columns and no problem marks.

Text from a node (such as its version) loses control, bidirectional and zero-width characters
before it is shown or saved.

## Proxies and groups

A node with `proxy_for` is a proxy (a "front door") for the nodes it lists. Every node is
still probed and, with a `stats_url`, still has its own stats. `/api/status` adds to each
host: `name` (or `null`), `role` (`"proxy"` or `"node"`), `proxy` (`{for: [addresses]}` or
`null`), `proxiedBy` (the proxy's address or `null`) and, on a proxy, `group`.

`group` is the combined latest stats of the proxy's members:
`{nodes, reporting, partial, missing, countOwn, data}`.

- **Which nodes count:** only members that are not down and have fresh stats (not stale)
  report. `reporting` is how many of the `nodes` did, `partial` is true when some did not,
  and `missing` names them. `data` is `null` when none reports.
- **Sums:** clients, received and sent bytes, announces per minute and the interface totals
  are added up. Clients stay `null` only when no reporting member knows them.
- **Peers heard cannot be de-duplicated.** Nodes publish counts only, so a peer heard by two
  nodes cannot be recognised and removed. `data.peersHeard` is `{sum, max}` (each with
  `total`, `lxmf`, `nomad`, `propagation`): the largest single node is a lower bound and the
  sum is an upper bound, and the page shows "N to M (overlap can't be removed)". An exact
  union would need nodes to publish something that can be merged (for example a sketch of
  the peers they have heard); that is a possible future change and is not built.
- **`count_own`** (default `false`): by default the group is only the nodes in `proxy_for`.
  Set `count_own: true` to add the proxy's own stats too. Leave it off when the proxy's
  stats already include the nodes behind it, or they would be counted twice.

### Exact peer counts with a stats token

A node can hand its list of peers to a website that asks with a secret token. With the lists
of all the nodes behind a proxy the website can count each peer once, so the group's peers
heard is an exact number instead of a range.

1. **On each node** (rettui), set its own secret with `RETTUI_STATS_TOKEN` or
   `--stats-token-file`. Use a different token for each node: whoever runs a node sees the
   token the website sends to it, and with one shared token that would be good for every
   other node too. It must be 16 to 256 printable ASCII characters without spaces. A
   request to the stats URL that carries `Authorization: Bearer <token>` then gets two extra
   fields, `"authorised": true` and `"peers"` (up to 20000 entries of `address`, `type` and
   `name`, sorted by address, with `"peers_truncated": true` when cut). Without a valid token
   the answer is the same as before.
2. **On the website**, give the website the token for each stats URL:
   - in the config file, `stats_token_file: <path>` on each node (recommended, so the secret
     is not in the YAML), or `stats_token: <token>`. A relative path is relative to the config
     file. The file holds only the token (a final newline is fine, at most 1 KiB) and is read
     once at start. A top-level `stats_token` or `stats_token_file` is a default for every
     node with a `stats_url`; it suits one operator running all the nodes, and the server
     logs a warning at start when one token would go to different hostnames;
   - with the environment variables, `STATS_TOKEN_FILES=host:port=path,host:port=path` for
     per-node tokens (strict like `STATS_URLS`: only nodes with a stats URL, none twice, no
     comma in a path), and `STATS_TOKEN` or `STATS_TOKEN_FILE` as a default for the others.
     None of them can be combined with `CONFIG_FILE`.
   Files should be readable by the server only (`chmod 600`); the server warns at start when
   another user can read one. In Docker, mount the folder with the files read-only next to the
   config (`./secrets:/config/secrets:ro` in `compose.yaml`). `config.yaml`, `*.token`,
   `*.secret`, `*.password`, `stats-token*.txt` and `secrets/` are in `.gitignore` and `.dockerignore`, so they are not
   committed or copied into the image.
   A bad token stops the server at start with a message that never repeats it. Prefer the
   file forms; in Docker mount the file read-only, like the config.
3. **The result.** When every member of a proxy group that reports stats also sent a complete
   list, `group.data.peersHeard` has `exact: true` and `union` (`total`, `lxmf`, `nomad`,
   `propagation`): the number of different peers, where a peer heard by several nodes counts
   once, and one heard as two types counts once in each type and once in the total. `sum` and
   `max` stay beside it. If any reporting member sent no list (no token, or the node did not
   accept it) or a cut one, `exact` is false and the range stays. `lists` is
   `{have, of}`: how many of the reporting members had a usable list.

Privacy and limits:

- The token is sent only as a header, and only over `https` (or `http` to loopback and private
  addresses); a redirect is never followed. It is never in a URL, a log line, an error message
  or an API answer.
- The peer lists are personal enough to keep private. Only the addresses and their types are
  read (names are dropped at once), invalid entries are dropped, duplicates are merged and at
  most 20000 entries per node are kept. They stay in memory in a compact form (about 17 bytes
  per peer, so under 350 KiB per node), are replaced on every fetch, and are never written to
  `history.json` or `stats-history.json` or shown in `/api/status` or `/api/stats`: only the
  counts are.
- With a token the website accepts an answer of up to 4 MiB from that node (64 KiB without),
  and at most 4 such fetches run at the same time. The group's union is worked out once per
  cycle, after the fetches, not when a page asks.
- The history graphs are not de-duplicated: they stay the sum and the largest single node,
  because past peer lists are not kept. The group's exact total is therefore shown as a
  number now, not as a line over time.

### On the status page

- A node with a `name` shows it, with the address beside it; a node without one shows its
  address as the name. Only proxies have a badge ("Proxy").
- The banner counts nodes and proxies apart, because a proxy is the front door and not a node:
  `3 nodes up, 1 proxy up`, or `2 of 3 nodes up, proxy down`. The headline and its colour still
  follow every entry point, so a proxy that is down is an outage even when all nodes are up.
  A node with no proxy counts as a node.
- A proxy and the nodes behind it are one card: `Front door [Proxy] passes visitors to 3
  nodes`, then one line (`3 of 3 nodes up · 34 clients · 1,300 to 3,300 peers heard · 33
  announces/min`). Peers heard is a range, and the "?" button explains why; when every node
  sent its peer list the number is exact and marked "de-duplicated". Nodes that did not report
  are named in a warning line. The nodes are nested in the card, and one can be open at a time.
- A node that is down shows the connection error and when it was last up; its last known
  stats are under "More". Stats that are old say so in words ("Stats from 12m ago"), and only
  the check bar is dimmed.
- Full details has a sticky header (view, range) and sections: Overview (what needs attention,
  versions, and for a proxy the nodes), Traffic, Peers, Storage and Disk; on phones the
  sections are a "Section" menu. The "View" menu of a proxy offers "Combined (N nodes)" (the
  default), the proxy itself and each node. Peers heard over time is one graph (a band between
  the least and the most for a group; by kind on request for one node).

## Network map

The status page has a collapsible "Network map" below the banner. It is drawn in the browser as
inline SVG from `/api/status`, so it refreshes with the page (every 15 seconds) and needs no
other request.

- **What is drawn:** the proxy (the front door) on one side, the nodes it passes visitors to in
  the middle, and, when any node has `upstreams`, the external peers on the other side. On a
  narrow screen the same tiers are stacked top to bottom. Without a proxy and without `upstreams`
  there is nothing to draw, and the map is not shown.
- **The proxy** is not drawn like a node: its box is wider and taller, has a double border in the
  accent colour and the tag "Proxy" in text. The outer border still has the state colour, and the
  state is still in words and a mark. Its name for screen readers and in "Show as list" starts
  with "Proxy" (`Proxy Front door, up, passes visitors to 3 nodes, ...`). The heading counts the
  proxies, nodes and external peers apart (`1 proxy, 3 nodes, 1 external peer, 4 links`).
- **Nodes** show their name, their state in words and a mark (`● Up`, `✕ Down`, `? Unknown`, so it
  is not colour alone) and a short fact: the clients, when the node's stats are fresh, else the
  connect time. A node that is down shows no clients. Up nodes pulse gently unless the visitor
  prefers reduced motion.
- **Lines** are solid from the proxy to its nodes and dashed to external peers. A line is grey
  when either end is down.
- **Upstreams** are for display only. A node's `upstreams` lists the external backbone peers it
  connects out to, so the map can draw them as grey "External" boxes. The server never resolves,
  probes or fetches an upstream's address, and an upstream has no state. The same name and
  address on two nodes is drawn once, with a line from each. `/api/status` adds an `upstreams`
  list (`[{name, address?}]`) to the hosts that have one, and nothing else.
- **Access:** the map draws only what a visitor already sees on the page: up or down, clients,
  connect time and the 90 day uptime. Nothing that `require_login` or `public_details` hides
  is used, and the names and addresses in `upstreams` are public, so leave out an address you do
  not want shown.
- **Keyboard and screen readers:** each box can be focused with Tab and has its facts as its
  name and as a tooltip title. "Show as list" opens the same map as a list, with what each
  node connects to. The map can be folded; whether it is open is kept only until the page is
  reloaded.

## How checking works

Every 30 seconds the server opens a TCP connection to each host (5 second timeout) and
closes it again. Up means the connection was made; the connect time is shown. The
hosts come only from the configuration; nothing a visitor sends is ever probed.
Up to 2880 checks per host (24 hours) are kept, and the uptime on a row is calculated over those.
The 90 day uptime bar and the incidents come from `uptime.json` (see "Uptime history and
incidents").

## Node stats

A rettui node can publish a small `stats.json` (opt-in on the node). With `STATS_URLS`
set, the status page shows clients and peers heard on each such host's line, and interfaces
online, traffic, announces per minute and how long the node has been running under "More". A host without a
stats URL shows nothing extra; a host whose stats cannot be fetched shows "Stats
unavailable". The production values are:

    STATS_URLS=rns.rettui.dev:4242=https://rns.rettui.dev/stats.json,front.rns.rettui.dev:4242=https://front.rns.rettui.dev/stats.json,back.rns.rettui.dev:4242=https://back.rns.rettui.dev/stats.json,side.rns.rettui.dev:4242=https://side.rns.rettui.dev/stats.json

On the same 30 second cycle as the probes, the server fetches each URL (5 second
timeout, at most 64 KiB, redirects are not followed). Each failure is independent and
never affects the up or down check. The answer is checked and rebuilt in a fixed shape:
numbers are clamped to whole non-negative numbers, text is cut to length and
unknown keys are dropped (the per-interface list is not kept, only the totals); anything that does not fit counts as unavailable. The last good
stats are kept in memory and marked stale after three missed cycles. They are not saved
to `history.json`. `/api/status` has a `stats` field on each host: `null` when no URL is
set, else `{ok, fetchedAt, stale, error?, data?}`. Each host also has `hasDetail`, true when a stats
URL is set (the page then offers a "Details" view).

**Announce queue.** A node on rettui 2.1.0 or later also reports the announces waiting to go
out (`announce_queue` and `interfaces.announce_queue`). `data.announceQueue` is then
`{queued, limit, full, fullest}`: whole numbers from 0 to 1,000,000 and a true or false, anything
else is ignored and the field is left out (an older rettui, or no interface with a queue, has none
either). It is kept and marked stale like the other stats, but not sampled into the history.
The page says "Announce queue full" in the node's row only when `full` is true, and shows the count
under "More". An alert for it is described in "Alerts".

### Stats history

For each host with a stats URL, the server keeps a sample about every 5 minutes (not on
every 30 second cycle), taken only when a fetch worked: clients, received and sent byte
counters, peers heard (total, LXMF, NomadNet, propagation), announces per minute, node
uptime and interfaces online. It keeps the last 7 days (2016 samples per host), and the
different versions a node has reported, with when each was first seen (at most 10).

- It is saved in `stats-history.json` in `DATA_DIR`, apart from `history.json`, which is
  unchanged. Both are written to a temporary file and renamed, readable by the owner only.
  Each saved entry is checked when loaded; bad entries are dropped and a missing or
  damaged file means starting empty. A file over 8 MiB is ignored.
- History needs `STATS_URLS`, and only starts collecting after this version is deployed:
  nothing older is backfilled, so graphs fill in over time.
- `/api/stats` turns the samples into bytes per second between neighbouring samples. The
  byte counters count since the node started, so a counter or uptime that goes down means
  the node restarted: that interval is left as a gap, never a negative or invented rate.
  An interval longer than 30 minutes (samples missing) is a gap too. Series are averaged
  down to at most 240 points per range. The answer has `stats` (the current stats),
  `version` (`current`, `uptimeSeconds`, `history` of `{version, firstSeen}`) and `series`
  (`bytesIn`, `bytesOut`, `clients`, `peers.{total,lxmf,nomad,propagation}`, `announces`,
  `interfacesOnline`, each a list of `[time ms, value or null]`).
- In the Details view, hovering a graph (or dragging a finger across it, or focusing it and using the Left, Right, Home and End keys) shows a guide line and a tooltip with the full date and time of the nearest sample and every value of that graph at that point; a gap reads "no data". Escape or leaving the graph hides it.
- `/api/stats?host=<proxy>&range=...&view=combined` is the same for a proxy's whole group
  (`view=node` is the default). It answers with `group` (the latest combined numbers),
  `members` (address, name, version and uptime of each) and `excluded` (members without a
  stats URL, which have no history), and `series` like the single view plus `peersLow`.
  A host that is not a proxy gets a 400 for `view=combined`.
  - The members' samples are matched by time: samples within half a sample interval of each
    other form one point.
  - **A point is added up only when every member with history has a sample in it** (and, for
    the byte rates, a usable rate: a restart of one member leaves a gap in the sum). Otherwise
    it is a gap. Summing whatever exists instead would make the line dip whenever one node
    missed a sample, which looks like an outage that did not happen. `series.sampleCount`
    is the number of complete points.
  - Clients, announces and interfaces online are sums; `peers` is the sum (upper bound) and
    `peersLow` the largest single member (lower bound), each with `total`, `lxmf`, `nomad`
    and `propagation`.
  - The answer is cached like the single view, so the cost does not grow with the visitors.
- `STATS_SAMPLE_INTERVAL_MS` changes the sample interval (default 300000). It exists only
  so the graphs can be tried quickly during testing; do not set it in production.

Security: use `https` URLs. Plain `http` is accepted only for loopback and private addresses (`localhost`, `127/8`, `::1`, `10/8`, `172.16/12`, `192.168/16`, and an IPv4 one of these written as IPv6, `::ffff:10.0.0.2`). The wider list of `manage_url` (tunnel ranges) does not hold here: the stats token goes with every request. URLs cannot carry a user name or password, and start-up errors never print the URL. A node exposes only aggregate numbers (no peer or identity details), and the
website fetches only the URLs set by the operator in `STATS_URLS`, never anything a
visitor sends. What a node answers is treated as untrusted and is shown as text only.

Words are set in Fira Sans and values (numbers with their units, versions, times, addresses) in Fira Code Nerd Font. Both are self-hosted
woff2 files in `public/fonts/`, under the SIL Open Font License (`OFL-FiraSans.txt` and `OFL.txt`); the page loads no font from another site.
Values carry the class `num` in the markup and in `status.js`.
