# rettui website

The website for [rettui](https://github.com/rettui-dev/rettui): a home page and a
status page that checks the project's Reticulum entry points. It has the same look
as rettui's web UI (colours, Fira Sans and Fira Code, dark and light themes).

It is plain HTML, CSS and JavaScript, served by a small Node.js server
(`server.js`) with no dependencies and no build step. The server also probes the
hosts, keeps their history and can fetch their node stats.

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
- `/api/status` is the same data as JSON, with `uptime90`, `days` and `incidents` for each host.
- `/api/incidents` lists the latest incidents (up to 100) of all nodes, newest first. Only GET
  and HEAD are allowed.
- `/api/stats?host=<host:port>&range=6h|24h|7d` is the detail of one node's stats (see
  "Stats history" below). `range` defaults to `24h`. An unknown host, or one without a
  stats URL, is a 404; a bad range is a 400. Only GET and HEAD are allowed.
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
release page as its `id` and as its `rel="alternate"` link, `updated` from the publish date, a
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
contrast; it is not a replacement for running axe in a browser.

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

Needs Node.js 24.7 or later (the login uses its built-in Argon2id).

    npm start        # http://localhost:8080
    npm test
    npm run hash-password -- --name alice   # a password_hash for the config file (see "Logins")

## Docker

    docker compose up -d --build

This serves the site on port 8080. History is kept in the `status-data` volume, so it
survives restarts. The container runs as an unprivileged user with a read-only root
file system; only `/data` is writable.

Without compose:

    docker build -t rettui-website .
    docker run -d -p 8080:8080 -v status-data:/data --read-only rettui-website

## Settings

All optional, set in the environment (or `environment:` in `compose.yaml`).

| Variable         | Default                           | Meaning                                                  |
| ---------------- | --------------------------------- | -------------------------------------------------------- |
| `PORT`           | `8080`                            | Port to listen on.                                       |
| `HOST`           | `0.0.0.0`                         | Address to listen on.                                    |
| `DATA_DIR`       | `./data` (`/data` in Docker)      | Where `history.json`, `stats-history.json`, `uptime.json` and `releases.json` are kept. |
| `STATUS_TARGETS` | the four hosts in `lib/monitor.js` | Comma separated `host:port` list to monitor.             |
| `CONFIG_FILE`    | none                              | Path of a YAML config file that lists the nodes instead of `STATUS_TARGETS` and `STATS_URLS` (see "Config file"). Users who can log in can only be set there (see "Logins"). |
| `STATS_TOKEN`    | none                              | Token sent to every stats URL to get peer lists (see "Exact peer counts"). `STATS_TOKEN_FILE` reads it from a file; `STATS_TOKEN_FILES` (`host:port=path,...`) gives one file per node. |
| `PUBLIC_DETAILS` | `true`                            | `false` removes the Details view (and `/api/stats`) for every node (see "What is public"). |
| `PUBLIC_DISK_FIGURES` | `false`                      | `true` publishes exact free and total disk space (see "What is public"). |
| `RELEASE_REPOS`  | `rettui-dev/rettui,rettui-dev/rngit-rs` | Comma separated `owner/name` list of the repositories the Downloads page shows (at most 8). Anything else is an error at start. |
| `GITHUB_TOKEN`   | none                              | Optional GitHub token that raises the API rate limit; it only reads public releases. `GITHUB_TOKEN_FILE` reads it from a file (not both). |
| `SITE_MODE`      | `full`                            | `status` serves only the status page and its APIs (see "Status-only site"). Not with `CONFIG_FILE`: use `site_mode` in the file. |
| `SITE_URL`       | none                              | The https address the site is served at, like `https://rettui.example` (no path). Needed for the absolute links in the feed and in the Open Graph tags; without it they are left out. Not with `CONFIG_FILE`: use `site.url` in the file. |
| `STATS_URLS`     | none                              | Comma separated `host:port=url` pairs: where to fetch each monitored host's node stats (see below). |

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
  its type (an SVG must start with `<svg`, and one with a script, a foreign object or an event
  handler is refused). It is served at `/brand/site-logo` with its real type, `nosniff`, the
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
  the links that must be absolute (the feed's own links now, the Open Graph tags below).
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
The image installs its one runtime dependency, `yaml`, with `npm ci --omit=dev`.

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
without checks) and `incidents` (the 5 newest). `/api/incidents` answers
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
          format: generic                         # generic (default), ntfy, discord or slack
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
  `ntfy` the text as the body, `slack` `{"text": ...}`, `discord` `{"content": ...}`.
- **Email:** a small built-in SMTP client (no dependency). The connection is always encrypted and
  the server's certificate is always checked: `tls` is SMTPS from the first byte, `starttls`
  upgrades the connection and refuses to go on if the server does not offer it. `username` with
  `password_file` logs in (`AUTH PLAIN` or `LOGIN`), after the encryption is up. A line break in
  any address, name or subject is refused, never cleaned. Replies and the message are capped, and
  the whole send has a 20 second limit.
- **Secrets:** `secret_file` and `password_file` are read once at start, relative to the config
  file (a file other users can read gets a warning), and held in memory only. They are never
  logged, never in an `/api` answer, never in `uptime.json`, and never repeated in an error.
- **Checked at start:** unknown keys, wrong types, more than 4 channels, more than 5 recipients,
  too-long strings and bad addresses stop the server with a message. Alerts are sent to the
  addresses in this file only.

**LXMF and other messengers.** The website server has no Reticulum stack, so it cannot send an
LXMF message itself. Point a webhook at a small bridge that does, for example a program that
runs next to a Reticulum node, listens on a private address (so `http` is allowed), checks the
`X-Rettui-Signature` header against the shared `secret`, and forwards the `message` field as an
LXMF message to your address. The same works for any other service that accepts a webhook.

**Other services (Telegram, Matrix, Pushover and so on).** The
[shoutrrr](https://github.com/nicholas-fedor/shoutrrr) fork `nicholas-fedor/shoutrrr` sends a
message to many services from one notification URL. What is confirmed from its README and its
Dockerfile: the image (`nickfedor/shoutrrr` on Docker Hub, `ghcr.io/nicholas-fedor/shoutrrr`) is a
command line tool (`ENTRYPOINT ["/shoutrrr"]`, no shell) used as `shoutrrr send --url "<url>"
--message "<text>"`. What is **not** confirmed, and so not claimed: that it has an HTTP listener
that could take this server's webhook. It does not look like it has one, so a webhook cannot
point at the container directly. Use it to check a notification URL, or from a small bridge of
your own that receives the webhook (checking `X-Rettui-Signature`) and runs `shoutrrr send`.
The URL holds the service's secret, so keep it in a file or the environment, not in
`compose.yaml`:

    # compose.yaml, next to the website service. Sends one test message and exits.
    #   docker compose run --rm notify
    notify:
      image: nickfedor/shoutrrr:latest
      profiles: ["tools"]
      command: ["send", "--url", "${SHOUTRRR_URL}", "--message", "rettui test message"]

The services and the URL for each are listed in the shoutrrr documentation
(<https://shoutrrr.nickfedor.com>). `${SHOUTRRR_URL}` is filled in by compose from a `.env` file next to `compose.yaml` (one line, `SHOUTRRR_URL=telegram://...`, `chmod 600`, and listed in `.gitignore`). This was not run here
(no Docker in the build environment).

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
`announce_queue_cleared`. There are no reminders for it.

    alerts:
      events: [down, recovered, announce_queue]
      announce_queue_samples: 3

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
          messagesReceivedFromPeers, messagesOfferedToPeers, unhandledMessages: number | null,
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
    "clients": n | null, "interfaces": { "total": n | null, "online": n | null },
    "announcesLastMinute": n | null,
    "peersHeardSum": { "total": n | null, "lxmf": ..., "nomad": ..., "propagation": ... }
  }
}
```

In `group`, peers heard is a range from the busiest single node (`min`) to the sum (`max`),
and one number when `exact` is true (see "Proxies and groups"). In `network`, every node counts
once: the nodes behind a proxy through the proxy's `group`, any other node through its own
numbers. `peersHeardSum` is an upper bound, as one peer heard by two nodes counts twice.
`reporting` is the number of nodes with fresh stats.

`GET /api/public/incidents`:

```
{ "version": 1, "generated": ISO time,
  "incidents": [ { "address": "host:port", "name": text, "start": ISO time,
                   "end": ISO time | null, "seconds": n, "ongoing": bool } ] }
```

## Logins

Some numbers can be kept for people with an account. With no `users` in the config file there
is no login at all and the page and API are exactly as without this feature: nothing is locked,
there is no login button, and `/login` does not exist. Users need the config file; with the
environment variables there is no login.

    users:
      - name: alice                  # 1 to 32 letters, digits, . - _; matched without regard to case
        password_hash: '$argon2id$v=19$m=19456,t=2,p=1$...$...'
    login:                           # optional, these are the defaults
      idle_timeout_minutes: 60       # a session ends after this long without a request
      max_age_hours: 12              # and this long after the login, whatever happens
      max_sessions: 1000             # with more, the session used least recently ends
      trusted_proxies: []            # see "Behind a reverse proxy"
    require_login: [details, storage, peers, disk, versions]   # the default once there are users
    nodes:
      - address: rns.rettui.dev:4242
        require_login: []            # a node can override the rule, like public_details

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
(the message never repeats the hash). The memory cap is 64 MiB because two checks run at once,
so logins never take more than 128 MiB. The config file holds hashes, not passwords, but keep it
private anyway.

**What is locked.** `require_login` lists sections, at the top for every node or on a node to
override it. Without a rule, once there are users, all of them are locked. A rule that names a
section while there are no users stops the server at start, and so does a `login` section.

| Section    | What a visitor without a login does not get |
| ---------- | ------------------------------------------- |
| `details`  | the Full details view and its graphs (`/api/stats` answers 401), and the node's place in a proxy's combined view |
| `storage`  | the message store of a propagation node: stored messages and size, message counters, the backlog waiting to send to peers, and their graphs |
| `peers`    | its peered propagation nodes: alive and total, static and automatic, limit, auto-peering, the peered nodes it lists, and their graph; also the messages sent to, received from and offered to peers, and the peer message flow graph (these go with `storage` too) |
| `disk`     | the disk level and share, free space, and data size; also the size of the message store (its bytes and graph), which on a propagation node is most of the data size |
| `versions` | the rettui version a node runs, and the versions seen |

Up or down, the check bar and uptime, clients, peers heard, traffic, announces, interfaces and how
long a node has been running stay public. The server takes the locked numbers out of
`/api/status` and `/api/stats` before they are sent; the page only shows what it got, with a
"Log in to see more" button where something is missing. A proxy's group line leaves out a sum
(message store, peered nodes, disk) as soon as one of its nodes, or the proxy, has that section
locked, since the sum would give the node's number away. A node whose details are locked is left
out of the combined view, as with `public_details: false`. `public_details: false` and
`public_disk_figures` still apply to logged-in users: a login shows what is locked, never what
is private.

With users, `/api/status` has `viewer` (`{name}`, `null` without a login) and each host has
`locked`, the sections this visitor cannot see (empty once logged in); a detail answer with
something left out has `locked` too. Both answers then carry `Cache-Control: private, no-store`
and `Vary: Cookie`, so no shared cache keeps one visitor's answer for another.

**How the login works.** The page posts the form to `/login`. It answers 200 with a session
cookie, `__Host-rettui_session`: a random 256-bit id, `HttpOnly`, `Secure`, `SameSite=Strict`,
`Path=/`. Every login gets a new id, and an id sent with the login is ended. `/logout` ends the
session. Sessions are kept in memory only. An open status page refreshes itself every 15 seconds,
so it keeps its session alive until `max_age_hours` is reached.

- A wrong name and a wrong password get the same 401 and the same message. An unknown name is
  checked against a stand-in hash with the highest costs of any user, so it takes at least as
  long as a wrong password for any real name.
- Five failed logins for a name (any name, existing or not), or twenty from one address (an IPv6
  address counts by its /64), start a wait that doubles with each further failure, up to 15
  minutes; during it the answer is 429 with `Retry-After`, without trying the password. Once
  the free tries are used up, a login waits for the checks already running for that name or
  address, so a burst sent at once gets no more tries than one sent one by one; more than 8
  waiting for one name or address get 503. A login that works clears the count. A failure is
  forgotten an hour after the last one. At most 10000 names and addresses are remembered; when
  that many are waiting, a new name or address is told to wait too, rather than one still
  waiting being forgotten.
- Each check takes about 19 MiB of memory (more with higher costs, at most 64 MiB). At most 2
  run at once and 8 wait; past that the answer is 503 with `Retry-After`, rather than running
  out of memory. A 503 does not count as a failed login.
- `/login` and `/logout` only take `application/x-www-form-urlencoded` (else 415), at most 4 KiB
  (else 413), and only from the page itself: `Sec-Fetch-Site` must be `same-origin`, or, from a
  browser too old to send it, `Origin` must name the host the request was sent to (else 403).
  Passwords over 1024 bytes are refused.
- Passwords and hashes are never logged.

**Behind a reverse proxy.** The cookie is always `Secure`, so the login only works over HTTPS
(browsers make an exception for `localhost`). Put the server behind a reverse proxy that
terminates TLS; the server itself does not read `X-Forwarded-Proto`. The proxy must pass the
`Host` header through (Caddy does; with nginx, `proxy_set_header Host $host;`) for browsers that
do not send `Sec-Fetch-Site`. Without `trusted_proxies` every request seems to come from the
proxy, so all visitors share one address for the failed-login wait. List the proxy's address in
`login.trusted_proxies` (IP addresses only, at most 16) to have the client address taken from
`X-Forwarded-For`, from the right, skipping trusted proxies. An IPv6 address may be written in
any form (`0:0:0:0:0:0:0:1` is `::1`). Never list an address that clients can connect from
directly. If a request with `X-Forwarded-For` comes from a loopback or private address that is
not listed, the server logs one warning saying so.

**Limits.** Everything is in one process and in memory: sessions end when the server restarts
(everyone has to log in again), and running several copies behind a load balancer does not
share sessions or failed-login counts. The login is for keeping numbers from casual visitors,
not for anything more sensitive: there is no password change, no second factor and no account
lockout beyond the wait.

- **Anyone can keep a known name locked out.** The wait counts failures per name, from any
  address, so whoever knows a name can keep its owner waiting: once the wait has grown to 15
  minutes, about four failed logins an hour keep it there. Pick names that are not easy to
  guess, such as not `admin` or your public handle.
- **`require_login` only covers this website.** It takes numbers out of what this server sends;
  it does nothing to the nodes. A node's `stats.json` answers whoever fetches it, so anyone who
  can reach a `stats_url` reads the locked numbers from the node itself. For numbers that must
  stay private, make each `stats_url` reachable only by this website (a private network, a
  firewall rule, or a reverse proxy in front of the node that asks for a secret).

The Docker image is built `FROM node:24-alpine`, which moves with each Node.js 24 release. To
build the exact same image every time, pin it by digest (`FROM node:24-alpine@sha256:...`, from
`docker buildx imagetools inspect node:24-alpine`) and update the digest yourself.

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

**Peered nodes are not shown.** With a stats token (see "Exact peer counts") a node also lists
the propagation nodes it peers with (`propagation_peers`: address, name, state, how long ago it
was heard or synced, counters). That list identifies other nodes, so the website only counts it
(up to 256 entries, valid 32 character hex addresses, each counted once) and keeps nothing else:
no address, name or state is stored, even in memory, or returned by the API or written to disk.
`stats.peerSummary` is `{listed, alive, static, unhandled, truncated}`. Text from a node (such as
its version) loses control, bidirectional and zero-width characters before it is shown or saved.

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
   `stats-token*.txt` and `secrets/` are in `.gitignore` and `.dockerignore`, so they are not
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

Security: use `https` URLs. Plain `http` is accepted only for loopback and private addresses (`localhost`, `127/8`, `::1`, `10/8`, `172.16/12`, `192.168/16`). URLs cannot carry a user name or password, and start-up errors never print the URL. A node exposes only aggregate numbers (no peer or identity details), and the
website fetches only the URLs set by the operator in `STATS_URLS`, never anything a
visitor sends. What a node answers is treated as untrusted and is shown as text only.

Words are set in Fira Sans and values (numbers with their units, versions, times, addresses) in Fira Code Nerd Font. Both are self-hosted
woff2 files in `public/fonts/`, under the SIL Open Font License (`OFL-FiraSans.txt` and `OFL.txt`); the page loads no font from another site.
Values carry the class `num` in the markup and in `status.js`.
