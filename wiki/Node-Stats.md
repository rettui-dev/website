What the website reads from your rettui nodes' stats pages and how it shows it: logs, propagation and disk numbers, groups behind a proxy, the network map and the stats history. To set a node up for it, see [Connecting Nodes](Connecting-Nodes).

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
  A session made by signing in with a passkey alone gives its password first (403 with `reauth: true`
  until then, and the Logs tab opens the password pop-up and asks again after it. The details of a node
  (`/api/stats`) are the same for such a session: 403 with `reauth: true` where a visitor gets 401; see
  [Accounts and second factor](Accounts-and-Second-Factor#signing-in-with-a-passkey-alone)). Logs that
  are public (`public_logs`) are open to everyone, so they ask nothing of anyone.
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
  `login.trusted_proxies`, visitors without a login share one address (see [Behind a reverse proxy](Logins#behind-a-reverse-proxy)).
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
  with a token, free and total space of the file system it is on (see [What is public](Public-Data-and-Stats-API#what-is-public)).

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

- **What is drawn:** each proxy (the front door) is a frame around the nodes it passes visitors
  to, so no lines are needed between the proxy and its nodes. The nodes sit in a row inside the
  frame, and the external peers they connect out to (`upstreams`) are boxes below the frame.
  Nodes behind no proxy sit in a plain row of their own. With several proxies, their frames are
  stacked. Without a proxy, `upstreams` and links between nodes there is nothing to draw, and the
  map is not shown.
- **The proxy frame** has a double border: the outer line has the proxy's state colour and the
  inner line the accent colour. Its header names it, with the tag "Proxy", its state in words and
  a mark, and the facts the page already shows (clients, connect time, 90 day uptime, for example
  `7 ms · 100% uptime`), with the address it is checked at under them. On the right it says how
  many nodes are inside ("Passes visitors to the 3 nodes inside"). A node that two proxies list is
  drawn in the first one's frame, and the other frame says so ("... and 1 in another frame"). Under
  the frames, the nodes behind no proxy sit in a row headed "Behind no proxy". Its name for screen readers and in "Show as list" starts with "Proxy"
  (`Proxy Front door, up, passes visitors to 3 nodes, ...`). The heading counts the proxies, nodes
  and external peers apart (`1 proxy, 3 nodes, 1 external peer, 4 links`).
- **Nodes** show their name, their state in words and a mark (`● Up`, `✕ Down`, `? Unknown`, so it
  is not colour alone) and a short fact: the clients, when the node's stats are fresh, else the
  connect time. A node that is down shows no clients. Up nodes pulse gently unless the visitor
  prefers reduced motion. Under the facts, in small type, is the address the status page checks
  (the same `host:port` as on the node's card); it is left out when the node has no name, because
  the name is the address then. Boxes are 176 pixels wide and get narrower, down to 104, when a row
  has many nodes; long names and addresses (IPv6 ones too) are cut short with "…", and the full
  address is in the box's tooltip and in what a screen reader says.
- **External peers** hang below the node that uses them, joined by a dashed line that crosses the
  foot of the frame. They show the address the operator gave, in small type under "not checked",
  when there is one. A peer that several nodes of one row use is one box: each node's dashed line
  turns once under the frame and ends at its own spot on the box. A peer used in two frames is
  drawn under each of them. A dashed line is grey when its node is down.
- **Links between nodes** are arrows in the accent colour: a dot at the node that dials, an
  arrowhead at the node that is dialled (once the link is up, traffic flows both ways). Two nodes
  side by side get a short arrow in the gap between them. A link that skips a node runs above the
  row as an arc and comes down into the top of the node: shorter arcs run lower, longer ones
  higher, and where two arcs cross, the lower one is drawn over the other with a gap around it,
  so you can see which line goes where. A solid arrow was found in the node's own config, an
  outlined arrow was declared by the operator, a dotted line with a bar is turned off in the
  dialling node's config, a grey line with two slashes has a node that is down, and a hollow
  circle at each end means the direction is not known. Two nodes that dial each other are one
  line with an arrowhead at both ends. Pointing at or focusing a node makes its links thicker and
  fades the others. A link the frame cannot draw (one to a proxy, or between nodes in different
  frames) is left out, and the page then says the links are listed on each node's card, where
  "Dials", "Dialled by" and "Linked with" chips name them. The text for screen readers and "Show
  as list" says the same (`Front: up, ... Dials Back, Side (turned off). Dialled by Netspeak
  (declared).`). How the links are found, and what is published, is in [Links between
  nodes](Connecting-Nodes#links-between-nodes).
- **One node at a time:** the whole map gives way to a view of one node when the map is narrower
  than 640 pixels (phones), when a frame or row would hold more than 8 nodes, when the arcs above
  a row would need more than 4 lanes, or when the boxes would not fit side by side. A row of
  buttons above the map names every node, with a mark for its state (two nodes with the same name
  also show the proxy they are behind, or their address); pick one with a click or a
  tap, or move along the buttons with the arrow keys, Home and End. The node picked is drawn large
  in the middle with all its facts and its address. Its proxy is above it, joined by a solid line
  ("passes visitors to"); a node behind two proxies shows both. The nodes that dial it are on the left ("Dialled by", with links in a direction
  not known), the nodes it dials on the right ("Dials", with nodes it dials both ways), and its
  external peers below ("connects out to"). On a phone the neighbours sit under the node instead:
  in one row when they fit, else in two columns. At most 8 neighbours are drawn on each side (6
  on a phone); the rest are counted, and "Show as list" names them all. At first the view shows
  the first node that has links between nodes, else the first node. The node picked stays picked
  when the page refreshes, until the page is reloaded; if it leaves the page, the first node is
  shown again. The view is chosen again whenever the map changes size.
- **Upstreams** are for display only. A node's `upstreams` lists the external backbone peers it
  connects out to, so the map can draw them as grey "External" boxes. The server never resolves,
  probes or fetches an upstream's address, and an upstream has no state. The same name and
  address on two nodes is drawn once, with a line from each. `/api/status` adds an `upstreams`
  list (`[{name, address?}]`) to the hosts that have one, and nothing else.
- **Access:** the map draws only what a visitor already sees on the page: up or down, clients,
  connect time and the 90 day uptime. Nothing that `require_login` or `public_details` hides
  is used, and the names and addresses in `upstreams` are public, so leave out an address you do
  not want shown.
- **Keyboard and screen readers:** each box, and each proxy frame, can be focused with Tab and
  has its facts as its name and as a tooltip title. In the one-node view the buttons are a tab
  list: Tab reaches the button of the node shown, and the arrow keys move along the list. "Show
  as list" opens the same map as a list, with what each node connects to. The map can be folded;
  whether it is open is kept only until the page is reloaded.

## How checking works

Every 30 seconds the server opens a TCP connection to each host (5 second timeout) and
closes it again. Up means the connection was made; the connect time is shown. The
hosts come only from the configuration; nothing a visitor sends is ever probed.
Up to 2880 checks per host (24 hours) are kept, and the uptime on a row is calculated over those.
The 90 day uptime bar and the incidents come from `uptime.json` (see [Uptime history and
incidents](Uptime-and-Alerts#uptime-history-and-incidents)).

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
under "More". An alert for it is described in [Alerts](Uptime-and-Alerts#alerts).

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
