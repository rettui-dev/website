How the server records how long each node has been up, and how it tells you when a node goes down. Alerts are set up in the config file (see [Configuration](Configuration#config-file)).

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

The server can send a message when a node goes down and when it is up again, and, when asked, when
a user adds a passkey (see "Passkey added" below). With an LXMF bridge it can also send each user
alerts about their own account to an LXMF address of their own (see "Users' own LXMF addresses" below). It is off unless the
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
      events: [down, recovered]                   # default both; announce_queue and passkey_added are added by listing them
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
  Node alerts only come from the monitor, and the passkey alert from the account API when a
  passkey is added: there is no endpoint to send or test one, and nothing a visitor sends decides
  where an alert goes (a user adding a passkey starts one message, to your channels, nothing more).
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
- **Checked at start:** unknown keys, wrong types, more than 4 channels, more than 5 recipients, `user_addresses` without a secret or on more than one channel,
  too-long strings and bad addresses stop the server with a message. Alerts are sent to the
  addresses in this file only.

**LXMF.** The website server has no Reticulum stack, so it cannot send an LXMF message itself.
[`bridges/lxmf`](https://github.com/rettui-dev/website/blob/main/bridges/lxmf/README.md) is a small bridge that does: it receives this webhook
(checking `X-Rettui-Signature` and the timestamp), and sends the `message` field as an LXMF message
to the addresses you list, with a Reticulum entry point or a propagation node. It has its own
Dockerfile and a Compose snippet, and it is not part of the website image; a built image is published
as `ghcr.io/rettui-dev/lxmf-bridge` (tags `dev`, `latest` and release versions), so you can pull it
instead of building it. The bridge can also send an alert to one LXMF address that the website names
in the webhook's optional `to` field (a user's own address, say). That is off unless the bridge's
`website_recipients` setting is on, and the website must check an address (by sending a code to it)
before it uses it. The bridge limits how many alerts one such address gets an hour, and how many
different ones, so a mistake cannot make it send to the whole network; see its README. Any other service that
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
  fixed address on a compose network, as for the [LXMF bridge](https://github.com/rettui-dev/website/blob/main/bridges/lxmf/README.md), or put it
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
[LXMF bridge](https://github.com/rettui-dev/website/blob/main/bridges/lxmf/README.md) can be listed side by side: an alert goes to every channel.

**Passkey added.** Off unless `passkey_added` is listed in `events` (the default stays
`[down, recovered]`, so a config that does not list it behaves as before). It is the one alert that
does not come from the monitor: the account API sends it when any user adds a passkey, which is the
step an attacker with a stolen password and code would take to stay in. The message names the user,
their role, the passkey's name and the time, for example `bob (manage) added a passkey named "Work
laptop" at 2026-11-19 12:03 UTC.`, and nothing else: never a credential id, an address of the user
or a secret. It goes to every channel in its format: the generic webhook body is `{event:
"passkey_added", user, role, passkey, message, sentAt, notAnnounced}` (signed as the others), `ntfy`
gets the text with the title "A passkey was added", `slack` and `discord` the text (the passkey's name
is typed by the user, so every text shows it in quotes as a JSON string, so a `"` cannot end the quote
and fake the rest of the sentence; Discord is told to ping nobody and gets the name's Markdown escaped,
so `[x](https://...)` is no link, and Slack gets `&`, `<` and `>` escaped, which makes `@everyone` or
`<!channel>` plain text), `apprise` a warning, and email the subject `[rettui]
bob added a passkey`. **Flood protection:** at most one alert for each user in each `cooldown_minutes`
(default 15; 0 sends every one). The passkeys added in between are counted, and when the cooldown
ends an alert goes out for the latest of them and says how many others were not announced ("2 more
passkeys were added by this user since the last alert, and not announced."; `notAnnounced` in the
webhook body); an add after the cooldown, if it comes first, sends that alert itself. The queue, the retries and the logging are the
same as for the other alerts (see "Sending" above), and a channel that is down, slow or refusing
never fails or delays adding the passkey: the alert is only queued, and the `passkey-added` line in
`audit.log` is written either way. It needs no `stats_url` and no node.

    alerts:
      events: [down, recovered, passkey_added]

**Users' own LXMF addresses.** Off unless one webhook channel says it is an LXMF bridge that takes
addresses the website names. The bridge needs `website_recipients = true` (see "Addresses the website
names" in its README); then, in this file:

    alerts:
      channels:
        - type: webhook
          url: http://172.28.0.10:8742/alert
          secret_file: secrets/hook.secret       # needed: the bridge only takes signed requests
          user_addresses: true                   # this channel is the bridge; at most one channel has it
          per_address_per_hour: 10               # default 10 (6 to 100): the most messages one address gets an hour
          addresses_per_hour: 50                 # default 50 (10 to 1000): the most different addresses an hour

`user_addresses` needs the `generic` format (the default) and a secret. Without it (or with `false`)
nothing below exists: the account page has no "LXMF alerts" card and the `/api/account/lxmf/...`
routes answer 404. Set `per_address_per_hour` and `addresses_per_hour` to the bridge's
`per_recipient_per_hour` and `recipients_per_hour`, or lower: **the website keeps under them itself**
(a sliding hour, in memory, so a restart starts it over), so a bug or a burst of events here cannot
make the bridge refuse, or send a flood to the network. A message over a limit is dropped and logged
(with the first 8 digits of the address, never the address). Every try counts, a retry too. A bridge
that answers 429 with `Retry-After` is left alone for that address until then. The channel still gets the node alerts
as before, with no `to`, so the bridge's `recipients` list must not be empty unless you want those
to fail.

**The hourly budget of one address is split**, so that alerts about an account are never crowded out.
Codes get at most 3 an hour for the address (from all users together, and never more than
`per_address_per_hour` minus 4), codes and node alerts together get `per_address_per_hour` minus 3,
and the account alerts may use all of it: at least 3 an hour are theirs, whoever asks for codes to
that address or however many node alerts there are. So `per_address_per_hour` must be at least 6:
a smaller number is refused when the site starts, with a message saying so (it is not scaled, so
nobody finds alerts missing later). An account alert is not tried again after the bridge was
unreachable or timed out, because the first try may have got through; other failures are tried up to
3 times.

The different addresses an hour (`addresses_per_hour`) are split the same way, so that other users'
code requests cannot use them up: codes may take new addresses only up to half of it (rounded down),
codes and node alerts together up to `addresses_per_hour` minus 5, and the account alerts may use all
of it, so 5 new addresses an hour are always theirs. So `addresses_per_hour` must be at least 10: a
smaller number is refused when the site starts.

On the account page ([Accounts and second factor](Accounts-and-Second-Factor)) each user
may enter up to 3 LXMF addresses of their own. Each is added and confirmed on its own: an address only
counts once the user has typed back a 6-digit code that the website sent to it through the bridge (`to` is
that address, `event` is `lxmf_check`; every address has its own code). The code works
for 15 minutes (confirming is limited to 5 tries an hour from one session and 10 an hour for the user, a wrong code included, and a wrong code is refused before the second step is asked), and a user gets at most 3 codes an hour for all their addresses
together (and the whole site 30 an hour). Every limit above is kept for each address. A code asked for an address that another user has already confirmed is answered as if
it was sent, and counts against the same limits as a real send (for the address, the different
addresses, the user and the site), with the same answer and the same "try again in" time when a
limit is reached, but nothing is posted to the bridge. So nobody can find out who has which address
by counting codes. The answer comes after a short random wait (20 to 150 ms); a bridge that is slow
or hangs still shows in the time a real send takes. The code is kept in memory only, as an HMAC, compared in constant time, and is in no log,
no audit line and no answer. While an address is not confirmed nothing else is sent there. Once it
is, it gets (every confirmed address of the user gets each message):

- **Alerts about the user's own account**, each with what happened and when, and for an admin's
  action which admin: a passkey added (`passkey_added`) or removed (`passkey_removed`, saying so when
  it was the last second step), the password changed by the user or reset by an admin
  (`password_changed`, `password_reset`; with how many passkeys went with it), the app code turned off
  (`second_factor_off`) or two-step sign-in reset by an admin (`second_factor_reset`), and new
  recovery codes (`recovery_codes_new`). When an address is added, every other confirmed address is told
  (`lxmf_address_changed`, with the first 8 digits of the new address); when a confirmed address is removed,
  every other confirmed address and the removed one are told. So someone who got into the account cannot
  add their own address or take the owner's away unseen. When the password is used to sign in from a browser
  that is not a known device of the user (the same "known device" as for sign in waits, see [Logins](Logins)),
  every confirmed address is told (`sign_in_new_device`): the password was just used to sign in to the
  site's address (`site.url`, when it is set) from a new browser at that time, and the user should change the
  password if it was not them. It is sent when the password is right, whether or not the second step is
  completed afterwards, and not for a sign in with a passkey alone. It has no IP address and no device id,
  at most one is sent per user in 15 minutes (the ones in between are counted, not sent), it uses the share
  of the budget kept for account alerts, and it never delays or fails the sign in. The other channels do not
  get it. For example: `[rettui status] The admin alice reset the password of your account bob at
  2026-11-19 12:03 UTC. 1 passkey was removed with it. You choose a new one when you next sign in.`
  They never hold a credential id, a secret, a code or an IP address. They are sent whatever
  `alerts.events` lists (that list is for the operator's own channels).
- **A test alert**, which the user asks for with "Send a test alert" on the account page (`account_test`): to every
  confirmed address, "Test alert for your account bob at https://status.example.org, sent at 2026-11-19 12:03 UTC. If
  you got this, account alerts reach this address." (the site's address only when `site.url` is set; no IP address or
  secret). A user may send 3 an hour, and the 30 an hour for the whole site are shared by all users (refused with 429
  and a wait). It is an account alert, but it is counted with the codes and node alerts: it takes part of the same
  `per_address_per_hour` minus 3 and `addresses_per_hour` minus 5 that they share, whatever order the messages come in,
  so at least 3 messages an hour per address and 5 new addresses an hour always remain for real account alerts. Tests
  alone may also take only a quarter of `addresses_per_hour` different addresses an hour, so they cannot crowd out the
  node alerts of admins. An address that has no room, or that the bridge told the site to leave alone, is held back and
  the page is told when it can go; a test that no address could take counts for nothing. Like the other account alerts
  it is not tried again after the bridge was unreachable. It needs only the password from the last 15 minutes.
- **Node alerts**, for users whose role is admin or manage who ticked "Node down and recovered
  alerts": the same events and the same text the channels get (`events`, the cooldown and the
  reminders all apply, as they are applied before a message is queued). A user whose role was lowered
  gets none, whatever they ticked.

A bridge that fails never fails or delays what the user did: the message is only queued, tried up to
3 times in the background (waits of 5 and 30 seconds; a refusal that will not get better, such as a
403 or 429, is not tried again, and counts for nothing against the website's limit), and a failure is
logged without the address, the URL or the secret. Delivery is best effort: a 202 from the bridge only
means it took the message. What the bridge answers while a code is sent is shown to the user plainly:
403 (the bridge has website addresses turned off), 429 (with its wait), 503 (busy, with its wait), 400
and 422 (not an address it can send to, or its own), 401 (the secret differs) and an unreachable
bridge. An address the bridge refuses is not kept. Only the user's own session can add, confirm or remove an
address, and it needs the same step-up as adding a passkey or the app code: the password, and the second step
as well when two-step sign-in is on (these three are limited to 5 an hour for a session, 10 for a user). Asking
for a new code for an address that is waiting for one and the node alerts tick need only the password from
the last 15 minutes. A session made with a passkey alone gives the password first and does not see the
addresses until then. A 4th address is refused with a plain message before any code is sent.

The addresses, whether each is confirmed and the node alerts tick are kept per user, for users made on the
website and for users in the config file, in `users.db` without a schema change (see [The user
store](User-Store)). They stay when the password changes or a passkey is
removed (that is when an alert matters most), and go when the user is deleted. Changes made with
`scripts/users.js` (`reset-password`, `reset-2fa`) send no message, as the command line has no alerter.
The audit log gets `lxmf-address-set`, `lxmf-code-sent`, `lxmf-address-confirmed`,
`lxmf-address-removed`, `lxmf-node-alerts` and `lxmf-test-sent` (the user, the number of addresses and the IP address it came from, never an LXMF address), with the user and the first 8 digits of the address (and, for the
first three, `with`: how the step-up was done). The password used from a new browser is no audit line of its own: a
new device is `device-added`, as before.

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
