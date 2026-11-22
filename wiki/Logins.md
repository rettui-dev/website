## Logins

Some numbers can be kept for people with an account. With no `users` in the config file and none
in the user store (`users.db`, see [Accounts and second factor](Accounts-and-Second-Factor#accounts-and-second-factor)) there is no login at all and
the page and API are exactly as without this feature: nothing is locked, there is no login button,
and `/login` does not exist. Any users at all need the user store key (see [The user store key](User-Store#the-user-store-key)). Users in the config file need the config file. Users in the user store work with the
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
      passkey_sign_in: true          # false turns off "Sign in with a passkey" (needs site.url)
    require_login: [details, storage, peers, disk, versions, links]   # the default once there are users
    nodes:
      - address: rns.rettui.dev:4242
        require_login: []            # a node can override the rule, like public_details
                                     # (this does not make its logs public, see [Node logs](Node-Stats#node-logs))

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
To give an admin the pepper, move them into the user store (see [Moving users out of the config
file](Managing-Users)).

**What is locked.** `require_login` lists sections, at the top for every node or on a node to
override it. Without a rule, once there are users (in the config file or in the user store), all of
them are locked, `links` included. A list you write replaces that default: `require_login: [links]`
alone locks the links and leaves every other section open. A node's own `require_login` replaces the
list in the same way for that node. With `detect_links` on, the server warns at start when such a list (at the top or on a node) leaves out `links`, because the links found in the nodes' configs are then shown to everyone. A rule that names a section while there are no users anywhere stops the server at
start, and so does a `login` section.

| Section    | What a visitor without a login does not get |
| ---------- | ------------------------------------------- |
| `details`  | the Full details view and its graphs (`/api/stats` answers 401), and the node's place in a proxy's combined view |
| `storage`  | the message store of a propagation node: stored messages and size, message counters, the backlog waiting to send to peers, and their graphs |
| `peers`    | its peered propagation nodes: alive and total, static and automatic, limit, auto-peering, the peered nodes it lists and their table in the Full details, and their graph; also the messages sent to, received from and offered to peers, and the peer message flow graph (these go with `storage` too) |
| `disk`     | the disk level and share, free space, and data size; also the size of the message store (its bytes and graph), which on a propagation node is most of the data size |
| `versions` | the rettui version a node runs, and the versions seen |
| `links` | the arrows and chips that show which node dials which (see [Links between nodes](Connecting-Nodes#links-between-nodes)). Part of the default. A link is left out when either of its nodes has `links` locked. Links found by `detect_links` are also left out for a node with `public_details: false`. A visitor who is not signed in gets only the other node, the direction and whether the interface is on; the source and conflict notes go to signed-in users. |

Up or down, the check bar and uptime, clients, peers heard, traffic, announces, interfaces and how
long a node has been running stay public. The server takes the locked numbers out of
`/api/status` and `/api/stats` before they are sent; the page only shows what it got.
A visitor who is not signed in is not shown what needs a login: no locked placeholder, no greyed
tab, no "log in" box in a row. The Logs tab, the Full details button of a node whose details are
locked, and the sections above are left out altogether. Where something is hidden, the status page
says so once, in one line under the banner ("Some details are only shown to signed-in users." and a
Sign in link), and the Overview of the details says the same; a site or visitor with nothing hidden
gets no line. A session made with a passkey alone that has not given its password counts as signed out
for these sections, and its line says "You signed in with a passkey. Some details need your password
too." with the button **Enter your password to see everything** (see
[Accounts and second factor](Accounts-and-Second-Factor#signing-in-with-a-passkey-alone)). The logs of a node are never said to exist to a visitor who may not read them, so they
are not counted as hidden. A proxy's group line leaves out a sum
(message store, peered nodes, disk) as soon as one of its nodes, or the proxy, has that section
locked, since the sum would give the node's number away. A node whose details are locked is left
out of the combined view, as with `public_details: false`. `public_details: false` and
`public_disk_figures` still apply to logged-in users: a login shows what is locked, never what
is private.

With users, `/api/status` has `viewer` (`{name}`, `null` without a login; `{name, passwordNeeded: true}`
for a passkey-only session that has not given its password, which is shown the public view) and each host has
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
  of them. The account page lists them (see [Known devices](Accounts-and-Second-Factor)).
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
  has as many. Wrong passwords asked while signed in count in a count of their own (see [Changes
  need a recent sign in](Accounts-and-Second-Factor)). Failures are summed up in `failures.log` (see [Audit log](Accounts-and-Second-Factor)).
- Each check takes about 19 MiB of memory (more with higher costs, at most 64 MiB). For sign ins
  from outside at most 2 run at once and 8 wait, and one address has at most 2 of those 10
  places; past that the answer is 503 with `Retry-After: 2`, rather than running out of memory.
  One more check may run for passwords asked while signed in (and new password hashes) and for
  known devices only, each with a queue of its own (4 places, 2 per session or device). They run
  in that place, and in a place of the sign ins from outside only while none of those is
  waiting. So a flood from outside never holds back a signed-in user or a known device, and
  signed-in users and known devices never hold back a sign in from outside for more than that
  one place. A 503 does not count as a failed login.
- `/login`, `/login/code`, `/login/passkey`, `/login/passkey/begin`, `/login/passkey/finish` and `/logout` only take `application/x-www-form-urlencoded` (else 415),
  at most 4 KiB, or 8 KiB for `/login/passkey` and `/login/passkey/finish` (else 413), with the header `X-Rettui-Request: 1`, and only from the page itself:
  `Sec-Fetch-Site` must be `same-origin`, or, from a browser too old to send it, `Origin` must
  name the host the request was sent to (else 403). A form on another site cannot send the
  header.
- Passwords, hashes and device ids are never logged.
- **Signing in with a passkey alone** (`POST /login/passkey/begin`, then `/login/passkey/finish`; see
  [Signing in with a passkey alone](Accounts-and-Second-Factor#signing-in-with-a-passkey-alone))
  sends no name. `begin` gives a token and the options for the browser's passkey prompt; the token
  is good for 5 minutes, for one answer, and only from the address that asked. At most 5 are open
  for one address and 1000 in all. When the 1000 are used, the oldest token of the network that holds
  the most (an IPv6 /48, or an IPv4 address) goes, so one network cannot push out the others. An
  address may ask for 10 at once and then one every 2 seconds; a whole IPv6 /56 for 40 at once and
  then one every half second, and a /48 for 120 at once and then one every quarter second. Past that
  the answer is 429 with `Retry-After`. Behind a proxy that is not in `trusted_proxies`, every
  visitor has the proxy's address, so these limits are shared by everyone, and a few visitors can
  use them up for all; set `trusted_proxies` (see "Behind a reverse proxy"). The same goes for
  people who share an IPv6 /48 (a mobile provider's pool, a cloud or university block): about 8
  different /64 networks inside it that keep asking drain the 120-at-once and quarter-second
  limit for the whole /48, and everyone in it gets 429 on `begin` until it fills up again. Signing
  in with a password is not affected, and neither is any other network. The limit is kept at this
  size on purpose: it is what stops one network from filling the memory for open tokens. `finish` takes the `token`
  and the `credential` (the browser's answer as JSON text). Every answer that depends on who the
  passkey belongs to (no such passkey, a wrong signature or user handle, no user verification, a
  user who is gone) is the same 401 with the same words, and counts as a failed sign in for the
  address (and for the known device, if the browser has one of the passkey's owner) only: never for
  a user or a passkey, so nobody can hold the owner back by knowing the id of a passkey. These
  failures add to the waits of the address in the list above, so wrong passwords and wrong passkeys
  from one address add up. A known device has a count of its own for wrong passkeys, apart from
  its count for wrong passwords: a sign in with a passkey clears only that one, so it never gives
  a browser fresh tries at the password, and it leaves the waits of the address as they are, so a
  passkey is no way to ease the count of wrong passwords.
  Passkey sign ins that work are paced for each user: three at once, then one a minute, from
  however many addresses. Past that the answer is 429 with `Retry-After` ("Too many passkey sign
  ins for this user right now"). Only signing in with a passkey is held back: the password and
  the sign ins of other users are not. A sign in with a passkey that is refused for this reason is
  counted in `failures.log` as `passkey-sign-in-paced`. A user has at most 5 sessions made with a
  passkey alone; a new one ends the oldest of those, never a session made with the password. The
  browsers such sign ins leave behind (known devices whose id starts with `pk`) are at most 3 for
  one user, push out only each other, and are never taken for a known device at the password
  step. A user who must change their password gets the same limited session as
  after the password. With `passkey_sign_in: false` (or without passkeys) both routes answer 404 and
  `/api/session` does not mention it.

### Behind a reverse proxy

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

Signing in with a passkey alone works at the address in `site.url` only. A visitor who reaches the
site by another name (the proxy's own host name, an IP address) gets no "Sign in with a passkey"
button, and an answer that comes that way is refused and counted as a failure. As for passwords,
wrong `trusted_proxies` make every visitor share one address for these waits.

A hop in `X-Forwarded-For` with a port, `192.0.2.1:5678` or `[2001:db8::1]:443`, is read as the
address alone; `[2001:db8::1]` without a port too. Any other hop that is not an IP address makes
the server take the proxy's own address for that request, and it logs one warning that starts
with `WARNING:`: set the proxy to send plain client addresses. If a request with `X-Forwarded-For`
comes from a loopback or private address that is not listed, the server logs one warning that
starts with `WARNING:` and names both settings.

**Limits.** Everything is in one process and in memory: sessions end when the server restarts
(everyone has to log in again), and running several copies behind a load balancer does not
share sessions or failed-login counts. Users can turn on a second factor (an app code, or passkeys) on their
account page, and website users can change their password there (see [Accounts and second
factor](Accounts-and-Second-Factor#accounts-and-second-factor)); there is no account lockout beyond the wait.

- **Guessing against lockouts.** The waits per name and address and per address only hold back
  that address, so nobody can lock someone else out by knowing their name. The pace of a name is
  the one that holds back everyone: about one guess a second at one name, however many addresses
  send them (about 3600 an hour). While it is used up, a browser that is not a known device gets
  429 for that name, the owner's new browser too; a known device of the owner still signs in at
  once. So sign in from your usual browser, keep a strong password (the account page asks for at
  least 12 characters), and turn on the second factor (see [Accounts and second factor](Accounts-and-Second-Factor#accounts-and-second-factor)), which
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
