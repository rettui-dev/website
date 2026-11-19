# rettui website

The website for [rettui](https://github.com/rettui-dev/rettui): a home page and a
status page that checks the project's Reticulum entry points. It has the same look
as rettui's web UI (colours, Fira Sans and Fira Code, dark and light themes).

It is plain HTML, CSS and JavaScript, served by a small Node.js server
(`server.js`) with no dependencies and no build step. The server also probes the
hosts, keeps their history and can fetch their node stats.

## Pages

- `/` is the home page.
- `/status` shows, for each entry point, whether it is up, one line of facts (clients, peers
  heard, uptime over 24 hours, when it was last checked) and a bar of the last 90 checks. A
  line of warning appears only when something needs a look. "More" opens the rest, and "Full
  details" opens graphs. It refreshes itself and keeps open rows open.
- `/api/status` is the same data as JSON.
- `/api/stats?host=<host:port>&range=6h|24h|7d` is the detail of one node's stats (see
  "Stats history" below). `range` defaults to `24h`. An unknown host, or one without a
  stats URL, is a 404; a bad range is a 400. Only GET and HEAD are allowed.
- `/healthz` answers `ok` (used by the Docker health check).
- `/login` and `/logout` (POST only) exist only when the config file has users (see "Logins").

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
| `DATA_DIR`       | `./data` (`/data` in Docker)      | Where `history.json` and `stats-history.json` are kept.  |
| `STATUS_TARGETS` | the four hosts in `lib/monitor.js` | Comma separated `host:port` list to monitor.             |
| `CONFIG_FILE`    | none                              | Path of a YAML config file that lists the nodes instead of `STATUS_TARGETS` and `STATS_URLS` (see "Config file"). Users who can log in can only be set there (see "Logins"). |
| `STATS_TOKEN`    | none                              | Token sent to every stats URL to get peer lists (see "Exact peer counts"). `STATS_TOKEN_FILE` reads it from a file; `STATS_TOKEN_FILES` (`host:port=path,...`) gives one file per node. |
| `PUBLIC_DETAILS` | `true`                            | `false` removes the Details view (and `/api/stats`) for every node (see "What is public"). |
| `PUBLIC_DISK_FIGURES` | `false`                      | `true` publishes exact free and total disk space (see "What is public"). |
| `STATS_URLS`     | none                              | Comma separated `host:port=url` pairs: where to fetch each monitored host's node stats (see below). |

A bad value (for example a `STATUS_TARGETS` entry that is not `host:port`, or a `STATS_URLS` entry that is not an `http` or `https` URL for a monitored host) stops the
server at start with a message.

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
      - address: front.rns.rettui.dev:4242

The file is checked when the server starts, and any mistake stops it with a message that
never repeats a URL:

- Only `nodes`, `stats_token`, `stats_token_file`, `public_details`, `public_disk_figures`, `users`,
  `login` and `require_login` at the top level, and only `address`, `name`, `stats_url`,
  `stats_token`, `stats_token_file`, `proxy_for`, `count_own`, `public_details`,
  `public_disk_figures` and `require_login` in a node; anything else is an error, as are repeated
  keys and wrong types.
- At most 64 nodes and a file of at most 64 KiB. The same host and port rules as
  `STATUS_TARGETS` apply, and the same URL rules as `STATS_URLS` (`https`, or `http` only
  for loopback and private addresses, no user name or password).
- Every `proxy_for` entry must be a listed node. A node cannot proxy itself, a node can have
  at most one proxy, and there can be no cycles. A proxy cannot itself be proxied (groups
  are one level deep).
- The file is read as plain data only: no aliases or anchors that are used, no merge keys
  (`<<`), no custom tags and only one document.

In Docker, mount the file read-only and point `CONFIG_FILE` at it (see `compose.yaml`).
The image installs its one runtime dependency, `yaml`, with `npm ci --omit=dev`.

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
showing it and prints the hash and a line to paste under `users:`. It also reads a password piped
to it (`printf '%s' "$PW" | node scripts/hash-password.js --name alice`; one final line break is
dropped), but never takes one as an argument, where it would land in the shell history. In Docker:
`docker compose run --rm -it website node scripts/hash-password.js --name alice`. The hash is
Argon2id with a random 16-byte salt and the OWASP minimum costs (`m=19456,t=2,p=1`); `--memory`,
`--passes` and `--parallelism` raise them. Only `argon2id` version 19 hashes are accepted, with
at least those costs and at most `m=262144,t=16,p=16`; anything else stops the server at start
(the message never repeats the hash). The config file holds hashes, not passwords, but keep it
private anyway.

**What is locked.** `require_login` lists sections, at the top for every node or on a node to
override it. Without a rule, once there are users, all of them are locked. A rule that names a
section while there are no users stops the server at start, and so does a `login` section.

| Section    | What a visitor without a login does not get |
| ---------- | ------------------------------------------- |
| `details`  | the Full details view and its graphs (`/api/stats` answers 401), and the node's place in a proxy's combined view |
| `storage`  | the message store of a propagation node: stored messages and size, message counters, unhandled messages, and their graphs |
| `peers`    | its peered propagation nodes: alive and total, static and automatic, limit, auto-peering, the peered nodes it lists, and their graph |
| `disk`     | the disk level and share, free space, and data size |
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
  checked against a stand-in hash with the same costs, so it takes as long.
- Five failed logins for a name (any name, existing or not), or twenty from one address (an IPv6
  address counts by its /64), start a wait that doubles with each further failure, up to 15
  minutes; during it the answer is 429 with `Retry-After`, without trying the password. A
  failure is forgotten an hour after the last one, and at most 10000 names and addresses are
  remembered.
- Each check takes about 19 MiB of memory (more with higher costs). At most 2 run at once and 8
  wait; past that the answer is 503 with `Retry-After`, rather than running out of memory.
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
`X-Forwarded-For`, from the right, skipping trusted proxies. Never list an address that clients
can connect from directly.

**Limits.** Everything is in one process and in memory: sessions end when the server restarts
(everyone has to log in again), and running several copies behind a load balancer does not
share sessions or failed-login counts. The login is for keeping numbers from casual visitors,
not for anything more sensitive: there is no password change, no second factor and no account
lockout beyond the wait.

## Propagation node and disk numbers

A node that runs an LXMF propagation node can add a `propagation` object to its stats, and any
node can add a `disk` object. Both are optional: an old node, a node with the propagation node
turned off (no `propagation` key, or `enabled` not true) or a node that has not measured its disk
yet just shows nothing for them. Each number inside is optional too; a missing or wrong one is
left out (shown as nothing) and never makes the rest of the stats unavailable.

- `propagation`: messages stored and their size (and the storage limit), peered nodes (alive,
  total, static, automatic, the peer limit, inbound links, whether auto-peering is on),
  messages received, served, sent to peers and received from peers, and unhandled messages.
  Counters count since the node started, except messages offered to peers, which may include
  earlier runs. Unhandled messages can lag behind the real number.
- `disk`: the size of the node's data (public on the node) and, only in the answer to a request
  with a token, free and total space of the file system it is on (see "What is public").

`/api/status` carries them in `stats.data.propagation` and `stats.data.disk`.

On the status page these numbers are under "More" (message store, disk) and in the Storage and
Disk sections of Full details. The row itself says nothing unless: the disk is 75% used or
more (90% or more reads "almost full"), fewer than half of the peered nodes are alive, or there
are unhandled messages.

For a proxy group, `group.data.propagation` adds up stored messages and bytes, peered nodes,
message counters and unhandled messages over the reporting nodes that have them (`nodes` says
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

## How checking works

Every 30 seconds the server opens a TCP connection to each host (5 second timeout) and
closes it again. Up means the connection was made; the connect time is shown. The
hosts come only from the configuration; nothing a visitor sends is ever probed.
Up to 2880 checks per host (24 hours) are kept, and uptime is calculated over those.

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
