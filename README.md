# rettui website

The website for [rettui](https://github.com/rettui-dev/rettui): a home page and a
status page that checks the project's Reticulum entry points. It has the same look
as rettui's web UI (colours, Fira Code Nerd Font, dark and light themes).

It is plain HTML, CSS and JavaScript, served by a small Node.js server
(`server.js`) with no dependencies and no build step. The server also probes the
hosts, keeps their history and can fetch their node stats.

## Pages

- `/` is the home page.
- `/status` shows, for each host, whether it is up, the connect time, when it was last
  checked, its uptime and a bar of the last 90 checks. It refreshes itself.
- `/api/status` is the same data as JSON.
- `/api/stats?host=<host:port>&range=6h|24h|7d` is the detail of one node's stats (see
  "Stats history" below). `range` defaults to `24h`. An unknown host, or one without a
  stats URL, is a 404; a bad range is a 400. Only GET and HEAD are allowed.
- `/healthz` answers `ok` (used by the Docker health check).

## Run locally

Needs Node.js 22 or later.

    npm start        # http://localhost:8080
    npm test

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
| `CONFIG_FILE`    | none                              | Path of a YAML config file that lists the nodes instead of `STATUS_TARGETS` and `STATS_URLS` (see "Config file"). |
| `STATS_TOKEN`    | none                              | Token sent to every stats URL to get peer lists (see "Exact peer counts"). `STATS_TOKEN_FILE` reads it from a file; `STATS_TOKEN_FILES` (`host:port=path,...`) gives one file per node. |
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

- Only `nodes`, `stats_token` and `stats_token_file` at the top level, and only `address`,
  `name`, `stats_url`, `stats_token`, `stats_token_file`, `proxy_for` and `count_own` in a node; anything else is an error, as are repeated keys and wrong types.
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
- `disk`: the size of the node's data, and free and total space of the file system it is on.

`/api/status` carries them in `stats.data.propagation` and `stats.data.disk`.

**Peered nodes are not shown.** With a stats token (see "Exact peer counts") a node also lists
the propagation nodes it peers with (`propagation_peers`: address, name, state, how long ago it
was heard or synced, counters). That list identifies other nodes, so the website keeps up to 256
rows in memory only, cleans them strictly (hex address, names without control, bidirectional or
zero-width characters and cut to 48 characters, a short word for the state), and publishes only
counts: `stats.peerSummary` is `{listed, alive, static, unhandled, truncated}`. No address or
name from the list is ever returned by the API or written to disk.

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

- A node with a `name` shows it, with the address beside it. Once at least one proxy is
  configured, every node gets a text badge, "Proxy" or "RNS node" (with the proxy's name in
  its title and screen reader text for nodes behind one). With only the environment
  variables there are no proxies, so no badges are shown: they would all say the same.
- A proxy shows an "All nodes (N)" line with the combined stats, how many nodes reported,
  and the nodes behind it nested underneath. Peers heard is shown as a range, not a number.
- The Details view of a proxy has a "View" menu: "Combined (N nodes)" (the default), the
  proxy itself and each node. Combined shows what each node runs, the peer ranges and the
  summed graphs.

## How checking works

Every 30 seconds the server opens a TCP connection to each host (5 second timeout) and
closes it again. Up means the connection was made; the connect time is shown. The
hosts come only from the configuration; nothing a visitor sends is ever probed.
Up to 2880 checks per host (24 hours) are kept, and uptime is calculated over those.

## Node stats

A rettui node can publish a small `stats.json` (opt-in on the node). With `STATS_URLS`
set, the status page shows a second line under each such host: clients, interfaces
online, traffic, peers heard, announces per minute and node uptime. A host without a
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

The fonts are Fira Code Nerd Font under the SIL Open Font License (`public/fonts/OFL.txt`).
