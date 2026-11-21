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
[`bridges/lxmf`](https://github.com/rettui-dev/website/blob/main/bridges/lxmf/README.md) is a small bridge that does: it receives this webhook
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
