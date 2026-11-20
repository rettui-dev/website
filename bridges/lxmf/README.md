# LXMF bridge for rettui website alerts

A small program that receives the website's alert webhook and sends each alert as an
[LXMF](https://github.com/markqvist/LXMF) message over [Reticulum](https://reticulum.network), so
a node going down shows up in Sideband, rettui, MeshChat or any other LXMF app.

    website monitor --(signed webhook)--> lxmf-bridge --(LXMF over Reticulum)--> your LXMF address

The bridge only sends. It listens for `POST /alert` (and `GET /healthz`), checks the signature and
the time the website puts on each request, and sends the alert's `message` as a short plain-text
message to each address in its list, with the alert's `event` (`down`, `still_down`, `recovered`,
...) as the title. It uses the same Reticulum and LXMF libraries as rettui (the `rettui-1.5`
branches of `rsReticulum` and `rsLXMF`, as git submodules in `deps/`).

## Set up

1. **Get the address of your LXMF app** (the recipient). Every LXMF app
   shows its own address (32 hex digits): rettui prints it with `rettui address`, and Sideband and
   MeshChat show it in their own settings or profile pages. Use the plain hex digits (a
   `<...>` around them is accepted). Only addresses in `recipients` ever get a message.
2. **Make a secret** (16 to 256 printable characters, no spaces) and keep it in two files, one for
   the website and one for the bridge, each readable by its own user only:

       mkdir -p -m 700 secrets
       (umask 077; openssl rand -hex 32 > secrets/hook.secret; cp secrets/hook.secret secrets/bridge.secret)
       chmod 600 secrets/hook.secret secrets/bridge.secret
       sudo chown 65532 secrets/bridge.secret

   (65532 is the user the bridge's image runs as. A secret file that other users can read gets a
   warning at start.)
3. **Write `bridge.toml`**, starting from [`bridge.example.toml`](bridge.example.toml). Only
   `secret_file`, `identity_file` and `recipients` are needed. Settings are checked at start: a
   mistake stops the bridge with a message that names the setting, and never repeats the secret.

   | Setting | Default | |
   | --- | --- | --- |
   | `listen` | `127.0.0.1:8742` | where the webhook is received |
   | `secret_file` | | the shared secret (16 to 256 printable characters, file of at most 1 KiB) |
   | `identity_file` | | the bridge's LXMF identity; made on the first start with mode 600 |
   | `display_name` | `rettui alerts` | name announced for the bridge's address |
   | `recipients` | | 1 to 16 LXMF addresses (32 hex digits) |
   | `entry_points` | `["rns.rettui.dev:4242"]` | 1 to 8 Reticulum TCP servers, `host:port` |
   | `propagation_node` | none | a propagation node's address, for store and forward |
   | `allow_from` | none | up to 16 exact IP addresses (no ranges) that may connect; others are closed on at once. Empty means any |
   | `max_age_seconds` | `300` | how old a request's time may be (1 to 3600); keep it small (see the limits) |
   | `max_body_bytes` | `16384` | the biggest request body (256 to 1048576) |

4. **Run it** (below), and **point the website at it**, in the website's config file:

       alerts:
         channels:
           - type: webhook
             url: http://172.28.0.10:8742/alert     # see the note below
             format: generic                         # the bridge reads this body
             secret_file: secrets/hook.secret        # the same secret as the bridge's

   The `generic` format is the only one the bridge reads: it takes `event` and `message` from it.
   **The website allows plain `http` only for an IP address in a private range (or `localhost`),
   not for a host name such as `lxmf-bridge`**, so under Compose the bridge gets a fixed address
   on the compose network (below). The bridge's address is never published to the outside.

5. **Check**: the first start logs the bridge's own address (`delivery address <...>`). Send a
   test alert by making the website send one (stop a monitored node for two checks), or sign one
   by hand (see "Trying it" below).

## Run it with Docker Compose

A ready-made image is published to GitHub's container registry as `ghcr.io/rettui-dev/lxmf-bridge`
(for `linux/amd64` and `linux/arm64`). Its tags: `dev` (the `dev` branch), `main` and `latest` (the
`main` branch and the newest release), and `1.2.3` and `1.2` (release `v1.2.3`). It is rebuilt when
anything under `bridges/` changes and for every release. To fetch it:

    docker pull ghcr.io/rettui-dev/lxmf-bridge:dev

(If the pull is refused, the package is still private: its owner has to make it public in the
package settings on GitHub.) To build it yourself instead, check out the two submodules and use
the `build:` line in the snippet below:

    git submodule update --init --recursive
    docker compose build lxmf-bridge

Next to the website service in `compose.yaml`:

    services:
      lxmf-bridge:
        image: ghcr.io/rettui-dev/lxmf-bridge:dev
        # To build it from this folder instead of pulling it, use these two lines:
        # build: ./bridges/lxmf
        # image: lxmf-bridge
        restart: unless-stopped
        read_only: true                  # nothing is written outside /data (and /tmp)
        tmpfs: [/tmp]
        cap_drop: [ALL]
        security_opt: ["no-new-privileges:true"]
        volumes:
          - lxmf-bridge-data:/data       # the identity: keep it, it is the bridge's address
          - ./bridges/lxmf/bridge.toml:/config/bridge.toml:ro
          - ./secrets/bridge.secret:/run/secrets/bridge.secret:ro
        networks:
          default:
            ipv4_address: 172.28.0.10    # a private address: the website accepts http for it
        # No ports: only the website, on the same compose network, reaches it.

    networks:
      default:
        ipam:
          config:
            - subnet: 172.28.0.0/24

    volumes:
      lxmf-bridge-data:

with `identity_file = "/data/identity"`, `secret_file = "/run/secrets/bridge.secret"` and
`listen = "0.0.0.0:8742"` in `bridge.toml` (inside the container, so the port is still private to
the compose network). The image is distroless and runs as user 65532; its health check is the
binary itself (`lxmf-bridge --healthcheck`).

Without Docker: `cargo build --release --locked` in this folder, then
`target/release/lxmf-bridge bridge.toml`. It stops on Ctrl-C or SIGTERM.

## What it does and does not do

- **Checks first.** A request needs `X-Rettui-Timestamp` and `X-Rettui-Signature`. The time must be
  no more than `max_age_seconds` old and no more than 60 seconds ahead, and the signature (the
  HMAC-SHA256 of `<timestamp>.<body>`, compared in constant time) must match, before the body is
  read as JSON. A signed request seen before (same time and signature) is refused with 409, so a
  captured request cannot be replayed within its time window. **That memory is in the bridge's
  RAM and is lost when it restarts**: someone who captured a request can send it once more, within
  `max_age_seconds` of its time, after a restart. Keep `max_age_seconds` small (60 is enough if the
  two clocks are in step; the website's own retries sign each try afresh).
- **Limits.** Headers up to 8 KiB, bodies up to `max_body_bytes` (checked from `Content-Length`
  before the body is read), 3 seconds to send the headers and 5 more for the body, 64 connections
  at once, one request per connection (the connection is closed after the answer). A request with
  a stale or future time, or a signature header that is not `sha256=` and 64 hex digits, is
  refused as soon as its headers are in, without waiting for the body. These need no secret, so
  anyone who can reach the port can hold connections for a few seconds each: set `allow_from` to
  the website's address (under Compose its address on the compose network, which you can fix as
  above), or keep the port on a private network. Only
  `POST /alert` and `GET /healthz` exist; anything else gets a 4xx with no body.
- **Answers.** 202 taken, 400 not an alert, 401 not authentic (a missing, wrong, stale or future
  signature or time all look alike), 409 replayed, 413 too big, 503 the queue (100 alerts) is full
  or busy, so the website's own retry applies.
- **Nothing sensitive in the log.** The secret, the signature and the body are never logged. A
  delivery's log line has the recipient's address and the reason it failed.
- **Sending.** Each alert goes to each recipient on its own. A delivery is tried up to 3 times (after
  5 and 30 seconds, as the website tries), and then given up; a failure is logged and never stops
  the bridge. Alerts are kept in memory only: a restart loses what is waiting.
- **The message.** Title: the event. Text: the webhook's `message`, cut to 1000 characters, with
  control characters removed. No other fields, no attachments.

## Limits you should know

- **Delivery depends on the recipient.** The bridge sends over a Link to the recipient's address, so
  it needs to hear of that address (a path) from the network: the recipient's app has to be online
  and announce (or answer a path request) while the bridge tries, which is about 45 seconds for
  each try. Without a `propagation_node`, an alert to a recipient that is offline then is lost
  after the third try.
- **A propagation node helps only if the bridge knows the recipient's key.** With
  `propagation_node` set, a message that cannot be delivered directly is encrypted for the recipient
  and left at that node, to be fetched when the recipient next syncs. That needs the recipient's key
  from an earlier announce (the bridge keeps what it hears in `/data/reticulum`), and the node must
  accept the message (it may ask for a stamp, which the bridge works out up to a cost of 28).
  A recipient that has never announced where the bridge could hear it cannot be sent to this way.
- **Both routes can deliver twice** in rare cases (a delivery proof that is lost after the message
  arrived is followed by the fallback). It is an alert, so a repeat is better than a miss.
- **The bridge is a Reticulum client, not a node.** It connects out to `entry_points` and does not
  route traffic. It announces its address when an entry point connects and every 3 hours. Its
  address is the identity in `identity_file`: lose the file and recipients see a new sender.
- **It receives nothing.** Replies sent to the bridge's address are dropped.
- **Plain HTTP.** The bridge speaks HTTP only, for a private network. Do not publish its port to the
  internet; if the webhook has to cross one, put TLS in front of it. The signature protects what is
  sent, but not from being read.
- **Not tested** against a real propagation node (see the tests below), and building the Docker image
  yourself needs the git submodules to be present (the published image does not).

## Trying it

Sign a request by hand with the secret (the signature is over `<timestamp>.<body>`). The secret is
read from its file by a small script, so it is never on a command line, in the shell history or in
the process list:

    printf '%s' '{"event":"down","message":"Front (front.rns.rettui.dev:4242) is down since 12:03 UTC."}' > body.json
    ts=$(date +%s)
    sig=$(node -e '
      const c = require("node:crypto"), fs = require("node:fs");
      const [ts, keyFile, bodyFile] = process.argv.slice(1);
      const key = fs.readFileSync(keyFile, "utf8").trim();
      console.log(c.createHmac("sha256", key).update(ts + ".").update(fs.readFileSync(bodyFile)).digest("hex"));
    ' "$ts" secrets/hook.secret body.json)
    curl -i -X POST http://127.0.0.1:8742/alert -H "X-Rettui-Timestamp: $ts" \
      -H "X-Rettui-Signature: sha256=$sig" --data-binary @body.json

A `202` means it was queued; the log then says `alert sent to <address>` or why it was not.

## Development

    cargo fmt --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked

The tests include the HTTP server against a fake sender (`tests/http.rs`), and an end-to-end test
(`tests/e2e.rs`) that starts a second Reticulum instance in the same process with a local TCP
server interface, connects the bridge to it, posts a signed alert, and checks that the receiver
gets the LXMF message (one short, as a packet, and one long, as a Resource). It uses no network
outside the machine. The propagation node route has no automated test.
