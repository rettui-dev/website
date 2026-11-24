What a visitor who is not signed in can see on the status page, and the public JSON API that shows exactly that, for your own dashboards.

## What is public

With users in the config file, some of what follows can also be kept for logged-in visitors;
see [Logins](Logins#logins).

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
tokens, peer lists, hashes, versions, upstreams, links between nodes, stats URLs or paths. A node with no stats URL, or
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
and one number when `exact` is true (see [Proxies and groups](Node-Stats#proxies-and-groups)). Each entry of `nodes` has a
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
