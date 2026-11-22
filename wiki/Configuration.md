Everything you can set: the environment variables, the status-only mode and branding, and the YAML config file that lists your nodes. To install and start the server first, see [Installing and Running](Installing-and-Running).

## Settings

All optional, set in the environment (or `environment:` in `compose.yaml`).

| Variable         | Default                           | Meaning                                                  |
| ---------------- | --------------------------------- | -------------------------------------------------------- |
| `PORT`           | `8080`                            | Port to listen on.                                       |
| `HOST`           | `0.0.0.0`                         | Address to listen on.                                    |
| `DATA_DIR`       | `./data` (`/data` in Docker)      | Where `history.json`, `stats-history.json`, `uptime.json` and `releases.json` are kept, and the user store `users.db`, `audit.log` and `failures.log` (see [Accounts and second factor](Accounts-and-Second-Factor#accounts-and-second-factor) and [The user store](User-Store#the-user-store)). |
| `USERS_KEY_FILE` | none                              | The file with the user store key (see [The user store key](User-Store#the-user-store-key)). Needed as soon as there are users, in the config file or in the user store; without it the server does not start then. Keep it outside `DATA_DIR`. |
| `USERS_KEY`      | none                              | The user store key itself, instead of `USERS_KEY_FILE` (not both). A file is safer: the environment of a process is easier to read and ends up in more places. |
| `STATUS_TARGETS` | the four hosts in `lib/monitor.js` | Comma separated `host:port` list to monitor.             |
| `CONFIG_FILE`    | none                              | Path of a YAML config file that lists the nodes instead of `STATUS_TARGETS` and `STATS_URLS` (see [Config file](#config-file)). Users who can log in can only be set there (see [Logins](Logins#logins)). |
| `STATS_TOKEN`    | none                              | Token sent to every stats URL to get peer lists (see [Exact peer counts](Node-Stats#exact-peer-counts-with-a-stats-token)). `STATS_TOKEN_FILE` reads it from a file; `STATS_TOKEN_FILES` (`host:port=path,...`) gives one file per node. |
| `PUBLIC_DETAILS` | `true`                            | `false` removes the Details view (and `/api/stats`) for every node (see [What is public](Public-Data-and-Stats-API#what-is-public)). |
| `PUBLIC_DISK_FIGURES` | `false`                      | `true` publishes exact free and total disk space (see [What is public](Public-Data-and-Stats-API#what-is-public)). |
| `RELEASE_REPOS`  | `rettui-dev/rettui,rettui-dev/rngit-rs` | Comma separated `owner/name` list of the repositories the Downloads page shows (at most 8). Anything else is an error at start. |
| `GITHUB_TOKEN`   | none                              | Optional GitHub token that raises the API rate limit; it only reads public releases. `GITHUB_TOKEN_FILE` reads it from a file (not both): a regular file of at most 1024 bytes; a pipe, a device or a bigger file stops the server at start. |
| `SITE_MODE`      | `full`                            | `status` serves only the status page and its APIs (see [Status-only site](#status-only-site)). Not with `CONFIG_FILE`: use `site_mode` in the file. |
| `SITE_URL`       | none                              | The https address the site is served at, like `https://rettui.example` (no path). Needed for the absolute links in the feed and in the Open Graph tags; without it they are left out. It is also the address passkeys are made for: without it there are no passkeys (see [Passkeys](Accounts-and-Second-Factor#passkeys)), and `http://localhost` is accepted for testing. Changing it later stops existing passkeys working. Not with `CONFIG_FILE`: use `site.url` in the file. |
| `STATS_URLS`     | none                              | Comma separated `host:port=url` pairs: where to fetch each monitored host's node stats (see [Node stats](Node-Stats#node-stats)). |
| `LOGIN_PASSKEY_SIGN_IN` | `true`                    | `false` turns off "Sign in with a passkey", signing in with a passkey alone, without a name and password (see [Signing in with a passkey alone](Accounts-and-Second-Factor#signing-in-with-a-passkey-alone)). It needs the site address (`SITE_URL`) like every passkey. Only `true` or `false`. Not with `CONFIG_FILE`: use `login.passkey_sign_in` in the file. |
| `LOGIN_TRUSTED_PROXIES` | none                       | Comma separated IP addresses or networks in CIDR notation (like `172.22.0.0/16`) of the reverse proxies in front of the site (at most 16), for users in the user store without a config file: the same as `login.trusted_proxies` (see [Behind a reverse proxy](Logins#behind-a-reverse-proxy)). Not with `CONFIG_FILE`: use `login.trusted_proxies` in the file. Set without users in the user store, it is not used and the server says so at start. |

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
  also the address of passkeys (see [Passkeys](Accounts-and-Second-Factor#passkeys)), where `http://localhost` is accepted too, for
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
        links:                              # optional: links to other nodes in this file
          - to: Back                        # a node's name or its address
          - to: side.rns.rettui.dev:4242
            direction: unknown              # optional: dials (the default) or unknown
      - address: front.rns.rettui.dev:4242

The file is checked when the server starts, and any mistake stops it with a message that
never repeats a URL:

- Only `nodes`, `stats_token`, `stats_token_file`, `public_details`, `public_disk_figures`, `users`,
  `login`, `require_login`, `detect_links` and `alerts` at the top level, and only `address`, `name`, `stats_url`,
  `stats_token`, `stats_token_file`, `proxy_for`, `count_own`, `public_details`,
  `public_disk_figures`, `require_login`, `upstreams`, `links`, `manage_url`, `manage_secret_file` and
  `manage_confirm_seconds` in a node; anything else is an error, as are repeated
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
- `links` is a list of 1 to 8 maps, each with a `to` (the name or the `host:port` address of another
  node in the file) and an optional `direction` (`dials`, the default, or `unknown`); no other key is
  allowed. A name that two nodes share, a `to` that is not a node, a link from a node to itself and the
  same node twice are errors. It is for the arrows between nodes on the status page; the website also
  finds links by itself when `detect_links` is on, see [Links between nodes](Connecting-Nodes#links-between-nodes).
- `detect_links` is `true` or `false` (default `false`). On, the website reads the Reticulum config of
  every node with a `manage_url` to find which node dials which, and publishes that. It needs at
  least one user, and only managed nodes are read. What it publishes is listed in [Links between
  nodes](Connecting-Nodes#links-between-nodes). It cannot be set with environment variables only.
- The file is read as plain data only: no aliases or anchors that are used, no merge keys
  (`<<`), no custom tags and only one document.

In Docker, mount the file read-only and point `CONFIG_FILE` at it (see `compose.yaml`).
The image installs its runtime dependencies, `yaml` and `@simplewebauthn/server`, with
`npm ci --omit=dev --ignore-scripts`.
