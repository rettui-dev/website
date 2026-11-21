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

   Make the link between the website and the node a WireGuard tunnel or put a TLS
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
  the shared range `100.64/10`, `fc00::/7` (WireGuard over IPv6) and `fe80::/10`. A public address or
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
online and is still meant to be, the change is **on probation** for `manage_confirm_seconds`. The
node itself checks each listener first: it sends Reticulum a test request there and waits for the
answer, and looks whether its interfaces are online and see traffic. Only when those checks pass can
the website's reachability probe keep the change; a listener that does not answer rolls it back
("Reticulum on <name> did not answer a test request", or "Reticulum isn't back as it was: it has no
address to test"). The page lists these checks under the status line ("Hilltop TCP: Reticulum
answered a test request", "Radio: online, no traffic yet"), and the node's list of changes shows
what it checked with the change and after a roll back. In that time the website's confirm job tries a TCP connection to the node's `address` from the config
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
